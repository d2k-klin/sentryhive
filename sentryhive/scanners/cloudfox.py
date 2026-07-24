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
                failures.append(f"{module} (exit {proc.returncode})")

        raw = _load_cloudfox_output(out_dir)
        findings = parse_cloudfox(
            raw,
            account_id=ctx.identity.account_id if ctx else "",
        )
        if not raw and failures:
            return ScanResult(
                self.name,
                ScanStatus.ERROR,
                message=f"CloudFox produced no JSON output; failed modules: {', '.join(failures)}",
            )
        message = f"partial module failures: {', '.join(failures)}" if failures else ""
        status = ScanStatus.ERROR if failures else ScanStatus.OK
        return ScanResult(self.name, status, findings=findings, raw=raw, message=message)


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
