"""Kubescape wrapper — Kubernetes posture and misconfiguration controls."""

from __future__ import annotations

import json
import os

from sentryhive.auth import AwsContext
from sentryhive.normalize import parse_kubescape
from sentryhive.scanners.base import ScanResult, ScanStatus
from sentryhive.scanners.kubernetes import KubernetesAccessError, KubernetesScanner


class KubescapeScanner(KubernetesScanner):
    name = "kubescape"
    binary = "kubescape"
    version_flag = "version"

    def _scan(self, ctx: AwsContext | None, workdir: str) -> ScanResult:
        safe = (self.cluster or "cluster").replace("/", "_")
        out_dir = os.path.join(workdir, f"kubescape-{safe}")
        os.makedirs(out_dir, exist_ok=True)
        try:
            env, region, account_id = self.prepare_access(ctx, out_dir)
        except KubernetesAccessError as exc:
            return ScanResult(self.name, ScanStatus.SKIPPED, message=str(exc))

        export = os.path.join(out_dir, "kubescape.json")
        proc = self._exec(
            [
                "kubescape",
                "scan",
                "framework",
                "all",
                "--format",
                "json",
                "--format-version",
                "v2",
                "--output",
                export,
            ],
            env=env,
            progress=True,
            progress_label=self.name,
        )
        raw = _load_json(export)
        if raw is None:
            return ScanResult(
                self.name,
                ScanStatus.ERROR,
                message=f"Kubescape produced no JSON output for '{self.cluster}' (exit {proc.returncode})",
            )
        findings = parse_kubescape(
            raw,
            cluster=self.cluster or "",
            account_id=account_id,
            region=region,
        )
        return ScanResult(self.name, ScanStatus.OK, findings=findings, raw=raw)


def _load_json(path: str):
    try:
        with open(path) as fh:
            return json.load(fh)
    except (json.JSONDecodeError, OSError):
        return None
