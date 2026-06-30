"""Prowler scanner wrapper — account-wide config & compliance (500+ checks)."""

from __future__ import annotations

import glob
import json
import os

from sentryhive.auth import AwsContext
from sentryhive.normalize import parse_prowler
from sentryhive.scanners.base import Scanner, ScanResult, ScanStatus, session_env


class ProwlerScanner(Scanner):
    name = "prowler"
    binary = "prowler"
    requires_aws = True

    def _scan(self, ctx: AwsContext | None, workdir: str) -> ScanResult:
        out_dir = os.path.join(workdir, "prowler")
        os.makedirs(out_dir, exist_ok=True)
        env = session_env(ctx)

        cmd = [
            "prowler",
            "aws",
            "--output-formats",
            "json-ocsf",
            "--output-directory",
            out_dir,
            "--output-filename",
            "prowler",
            "--ignore-exit-code-3",  # don't fail the process just because findings exist
            "--no-color",
            "--log-level",
            "INFO",
        ]
        if ctx and ctx.regions:
            cmd += ["--region", *ctx.regions]

        proc = self._exec(cmd, env=env, progress=True, progress_label=self.name)
        raw = _load_prowler_output(out_dir)
        if raw is None:
            return ScanResult(
                self.name,
                ScanStatus.ERROR,
                message=f"prowler produced no JSON output (exit {proc.returncode}). stderr: {proc.stderr[-500:]}",
            )
        findings = parse_prowler(raw)
        return ScanResult(self.name, ScanStatus.OK, findings=findings, raw=raw)


def _load_prowler_output(out_dir: str):
    matches = sorted(
        glob.glob(os.path.join(out_dir, "*.ocsf.json")) + glob.glob(os.path.join(out_dir, "*.json")),
        key=os.path.getmtime,
        reverse=True,
    )
    for path in matches:
        try:
            with open(path) as fh:
                return json.load(fh)
        except (json.JSONDecodeError, OSError):
            continue
    return None
