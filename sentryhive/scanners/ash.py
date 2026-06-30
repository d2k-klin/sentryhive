"""ASH (Automated Security Helper) wrapper — static analysis of local IaC/code.

Unlike the other scanners, ASH does not touch a live AWS account; it scans source
files on disk (Terraform, CloudFormation, secrets, etc.). Point it at a directory
with --source-dir (defaults to the current working directory).
"""

from __future__ import annotations

import glob
import json
import os

from sentryhive.auth import AwsContext
from sentryhive.normalize import parse_ash
from sentryhive.scanners.base import Scanner, ScanResult, ScanStatus


class AshScanner(Scanner):
    name = "ash"
    binary = "ash"
    requires_aws = False

    def __init__(self, source_dir: str | None = None):
        self.source_dir = source_dir or os.environ.get("SENTRYHIVE_SOURCE_DIR") or os.getcwd()

    def _scan(self, ctx: AwsContext | None, workdir: str) -> ScanResult:
        if not os.path.isdir(self.source_dir):
            return ScanResult(self.name, ScanStatus.ERROR, message=f"source dir not found: {self.source_dir}")
        out_dir = os.path.join(workdir, "ash")
        os.makedirs(out_dir, exist_ok=True)

        self._exec(
            ["ash", "--source-dir", self.source_dir, "--output-dir", out_dir],
        )
        raw = _load_ash_results(out_dir)
        if raw is None:
            return ScanResult(
                self.name,
                ScanStatus.SKIPPED,
                message="ASH produced no parseable JSON results (nothing to scan or unsupported version).",
            )
        findings = parse_ash(raw)
        return ScanResult(self.name, ScanStatus.OK, findings=findings, raw=raw)


def _load_ash_results(out_dir: str):
    candidates = glob.glob(os.path.join(out_dir, "**", "*aggregated*results*.json"), recursive=True) + glob.glob(
        os.path.join(out_dir, "**", "*.json"), recursive=True
    )
    for path in sorted(candidates, key=os.path.getmtime, reverse=True):
        try:
            with open(path) as fh:
                return json.load(fh)
        except (json.JSONDecodeError, OSError):
            continue
    return None
