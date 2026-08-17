"""CloudFox wrapper — AWS attack-surface and privilege-path observations.

CloudFox is an enumeration tool, not a compliance scanner. SentryHive runs only
the focused, non-secret-collecting modules needed for the combined report and the
normalizer classifies strong risk signals separately from informational exposure.
"""

from __future__ import annotations

import glob
import json
import os

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

_IAM_HINT = "Grant the SentryHiveCloudFoxCoverage permissions in iam/least-privilege-policy.json and re-run."


def _failure_reason(proc) -> str:
    """Why a module failed, taken from the output the process actually produced.

    Previously only the exit code survived, so "endpoints (exit 1)" gave the operator
    nothing to act on and read like a defect in SentryHive rather than a missing grant.
    """
    text = (proc.stderr or proc.stdout or "").strip()
    lines = [line.strip() for line in text.splitlines() if line.strip()]
    tail = " / ".join(lines[-3:])[:MAX_REASON_CHARS]
    if any(marker in text.lower() for marker in _DENIED_MARKERS):
        return f"access denied — {tail}" if tail else "access denied"
    return tail or f"exit {proc.returncode}"


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
                failures.append(f"{module}: {_failure_reason(proc)}")

        raw = _load_cloudfox_output(out_dir)
        findings = parse_cloudfox(
            raw,
            account_id=ctx.identity.account_id if ctx else "",
        )
        if not raw and failures:
            return ScanResult(
                self.name,
                ScanStatus.ERROR,
                message=self._failure_message(failures, produced_nothing=True),
            )
        if failures:
            # Some modules worked, so findings are real but the evidence is incomplete.
            # That is still a scanner that could not do its whole job: report it as an
            # error with an actionable reason rather than passing a partial scan off as clean.
            return ScanResult(
                self.name,
                ScanStatus.ERROR,
                findings=findings,
                raw=raw,
                message=self._failure_message(failures),
            )
        return ScanResult(self.name, ScanStatus.OK, findings=findings, raw=raw)

    def _failure_message(self, failures: list[str], produced_nothing: bool = False) -> str:
        completed = len(self.modules) - len(failures)
        head = (
            "CloudFox produced no JSON output"
            if produced_nothing
            else f"{completed} of {len(self.modules)} modules completed"
        )
        message = f"{head}; failed — {'; '.join(failures)}"
        if any("access denied" in failure for failure in failures):
            message = f"{message}. {_IAM_HINT}"
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
