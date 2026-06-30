"""Cloudsplaining scanner wrapper — IAM policy risk analysis.

Two-step tool: first download the account authorization details, then scan it.
"""

from __future__ import annotations

import json
import os

from sentryhive.auth import AwsContext
from sentryhive.normalize import parse_cloudsplaining
from sentryhive.scanners.base import Scanner, ScanResult, ScanStatus, session_env


class CloudsplainingScanner(Scanner):
    name = "cloudsplaining"
    binary = "cloudsplaining"
    requires_aws = True

    def _scan(self, ctx: AwsContext | None, workdir: str) -> ScanResult:
        out_dir = os.path.join(workdir, "cloudsplaining")
        os.makedirs(out_dir, exist_ok=True)
        env = session_env(ctx)
        account_id = ctx.identity.account_id if ctx else ""

        dl = self._exec(
            ["cloudsplaining", "download", "--output", out_dir],
            env=env,
            progress=True,
            progress_label=f"{self.name} download",
        )
        auth_file = _find_downloaded_auth_file(out_dir)
        if auth_file is None:
            return ScanResult(
                self.name,
                ScanStatus.ERROR,
                message=(
                    f"cloudsplaining download produced no authorization JSON "
                    f"(exit {dl.returncode}): {dl.stderr[-400:]}"
                ),
            )

        # `scan` writes results JSON into the output directory.
        self._exec(
            ["cloudsplaining", "scan", "--input-file", auth_file, "--output", out_dir, "--skip-open-report"],
            env=env,
            progress=True,
            progress_label=f"{self.name} scan",
        )
        raw = _load_results_json(out_dir)
        if raw is None:
            return ScanResult(self.name, ScanStatus.ERROR, message="cloudsplaining produced no JSON results")
        findings = parse_cloudsplaining(raw, account_id=account_id)
        return ScanResult(self.name, ScanStatus.OK, findings=findings, raw=raw)


def _find_downloaded_auth_file(out_dir: str) -> str | None:
    import glob

    candidates = sorted(glob.glob(os.path.join(out_dir, "*.json")), key=os.path.getmtime, reverse=True)
    for path in candidates:
        name = os.path.basename(path)
        if not name.startswith(("iam-results-", "iam-findings-")):
            return path
    return None


def _load_results_json(out_dir: str):
    import glob

    preferred = glob.glob(os.path.join(out_dir, "iam-results-*.json")) + glob.glob(
        os.path.join(out_dir, "iam-findings-*.json")
    )
    fallback = [
        path
        for path in glob.glob(os.path.join(out_dir, "*.json"))
        if os.path.basename(path).startswith(("iam-results-", "iam-findings-"))
    ]
    for path in sorted(preferred or fallback, key=os.path.getmtime, reverse=True):
        try:
            with open(path) as fh:
                return json.load(fh)
        except (json.JSONDecodeError, OSError):
            continue
    return None
