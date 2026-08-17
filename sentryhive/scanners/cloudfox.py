"""CloudFox wrapper — AWS attack-surface and privilege-path observations.

CloudFox is an enumeration tool, not a compliance scanner. SentryHive runs only
the focused, non-secret-collecting modules needed for the combined report and the
normalizer classifies strong risk signals separately from informational exposure.
"""

from __future__ import annotations

import glob
import json
import os
import signal

from sentryhive.auth import AwsContext
from sentryhive.normalize import parse_cloudfox
from sentryhive.scanners.base import Scanner, ScanResult, ScanStatus, session_env

#: Longest failure reason kept from a module's stderr.
MAX_REASON_CHARS = 300

#: Substrings that identify an access problem rather than a tool defect. A permissions
#: gap is the overwhelmingly common cause of a module exiting non-zero, and it needs a
#: different message: the operator must fix IAM, not file a bug.
_DENIED_MARKERS = (
    "accessdenied",
    "access denied",
    "unauthorized",
    "not authorized",
    "authorizationerror",
    "explicit deny",
)

#: Signatures of a defect inside CloudFox itself rather than anything about the account.
#: These are not operator-fixable: CloudFox parses IAM policy JSON with a YAML
#: unmarshaller, so valid JSON that is not valid YAML aborts the module.
_UPSTREAM_MARKERS = (
    "unmarshalling yaml",
    "unmarshaling yaml",
    "panic:",
    "runtime error",
    "invalid memory address",
    "nil pointer",
)

_IAM_HINT = "Grant the SentryHiveCloudFoxCoverage permissions in iam/least-privilege-policy.json and re-run."

_UPSTREAM_HINT = (
    "This is a defect inside CloudFox, not a problem with the account or with SentryHive, "
    "and no fixed CloudFox release exists yet. Compliance, IAM and backup evidence are "
    "unaffected — only attack-surface enumeration is partial. For a clean exit, re-run with "
    "--scanners prowler,cloudsplaining,resilience."
)


def _exit_description(returncode: int) -> str:
    """Readable process outcome. Python reports signal deaths as a negative returncode,
    so a raw '-11' reaches the operator as nonsense instead of 'segmentation fault'."""
    if returncode >= 0:
        return f"exit {returncode}"
    try:
        name = signal.Signals(-returncode).name
    except ValueError:
        return f"killed by signal {-returncode}"
    return f"crashed — killed by {name} (signal {-returncode})"


def classify_failure(proc) -> tuple[str, str]:
    """Return (reason, kind) for a failed module, where kind is access|upstream|unknown.

    The kind decides which remedy the operator is told about: a permissions gap they can
    fix, versus a scanner defect they cannot.
    """
    text = (proc.stderr or proc.stdout or "").strip()
    lines = [line.strip() for line in text.splitlines() if line.strip()]
    tail = " / ".join(lines[-3:])[:MAX_REASON_CHARS]
    lowered = text.lower()

    if any(marker in lowered for marker in _DENIED_MARKERS):
        return (f"access denied — {tail}" if tail else "access denied"), "access"

    outcome = _exit_description(proc.returncode)
    if any(marker in lowered for marker in _UPSTREAM_MARKERS) or proc.returncode < 0:
        return (f"{outcome} — {tail}" if tail else outcome), "upstream"
    return (f"{outcome} — {tail}" if tail else outcome), "unknown"


class CloudfoxScanner(Scanner):
    name = "cloudfox"
    binary = "cloudfox"
    requires_aws = True

    # Deliberately excludes env-vars, secrets, userdata, and other loot-producing
    # modules that could pull sensitive values into the scanner workspace.
    modules = ("workloads", "role-trusts", "resource-trusts", "endpoints", "network-ports")

    def _scan(self, ctx: AwsContext | None, workdir: str) -> ScanResult:
        out_dir = os.path.join(workdir, "cloudfox")
        os.makedirs(out_dir, exist_ok=True)
        env = session_env(ctx)
        failures: list[str] = []
        kinds: set[str] = set()

        for module in self.modules:
            proc = self._exec(
                [
                    "cloudfox",
                    "aws",
                    "--outdir",
                    out_dir,
                    "--yes",
                    "--verbosity",
                    "1",
                    module,
                ],
                env=env,
                progress=True,
                progress_label=f"{self.name}:{module}",
            )
            if proc.returncode != 0:
                reason, kind = classify_failure(proc)
                failures.append(f"{module}: {reason}")
                kinds.add(kind)

        raw = _load_cloudfox_output(out_dir)
        findings = parse_cloudfox(
            raw,
            account_id=ctx.identity.account_id if ctx else "",
        )
        if failures:
            # A scanner that could not do its whole job is reported as an error, so a
            # partial scan is never passed off as clean — but the message must say which
            # kind of failure it was, because only one of them is the operator's to fix.
            return ScanResult(
                self.name,
                ScanStatus.ERROR,
                findings=findings,
                raw=raw,
                message=self._failure_message(failures, kinds, produced_nothing=not raw),
            )
        return ScanResult(self.name, ScanStatus.OK, findings=findings, raw=raw)

    def _failure_message(self, failures: list[str], kinds: set[str], produced_nothing: bool = False) -> str:
        completed = len(self.modules) - len(failures)
        head = (
            "CloudFox produced no JSON output"
            if produced_nothing
            else f"{completed} of {len(self.modules)} modules completed"
        )
        message = f"{head}; failed — {'; '.join(failures)}"
        if "access" in kinds:
            message = f"{message}. {_IAM_HINT}"
        if "upstream" in kinds:
            message = f"{message}. {_UPSTREAM_HINT}"
        return message


def _load_cloudfox_output(out_dir: str) -> dict[str, list[dict]]:
    """Return module-name -> rows from CloudFox's nested JSON output tree."""
    raw: dict[str, list[dict]] = {}
    for path in glob.glob(os.path.join(out_dir, "cloudfox-output", "aws", "**", "json", "*.json"), recursive=True):
        try:
            with open(path) as fh:
                rows = json.load(fh)
        except (json.JSONDecodeError, OSError):
            continue
        if isinstance(rows, list):
            raw[os.path.splitext(os.path.basename(path))[0]] = [row for row in rows if isinstance(row, dict)]
    return raw
