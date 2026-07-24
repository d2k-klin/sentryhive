"""hardeneks scanner wrapper — EKS best-practice checks.

Unlike Prowler/Cloudsplaining, hardeneks reads from *inside* the Kubernetes
cluster, so a read-only IAM role is not enough: the audit principal also needs an
in-cluster RBAC grant (EKS access entry or aws-auth/RBAC binding) on each cluster.
SentryHive therefore treats EKS as an opt-in second phase with its own preflight
access check — see docs/eks-access.md.
"""

from __future__ import annotations

import json
import os

from sentryhive.auth import AwsContext
from sentryhive.normalize import parse_hardeneks
from sentryhive.scanners.base import ScanResult, ScanStatus
from sentryhive.scanners.kubernetes import KubernetesAccessError, KubernetesScanner


class HardeneksScanner(KubernetesScanner):
    name = "hardeneks"
    binary = "hardeneks"

    def _scan(self, ctx: AwsContext | None, workdir: str) -> ScanResult:
        safe = (self.cluster or "cluster").replace("/", "_")
        out_dir = os.path.join(workdir, f"hardeneks-{safe}")
        os.makedirs(out_dir, exist_ok=True)
        try:
            env, region, account_id = self.prepare_access(ctx, out_dir)
        except KubernetesAccessError as exc:
            return ScanResult(self.name, ScanStatus.SKIPPED, message=str(exc))

        export = os.path.join(out_dir, "hardeneks.json")
        self._exec(
            ["hardeneks", "--export-json", export, "--region", region or "us-east-1"],
            env=env,
            progress=True,
            progress_label=self.name,
        )
        raw = _load_json(export)
        if raw is None:
            return ScanResult(
                self.name, ScanStatus.ERROR, message=f"hardeneks produced no JSON output for '{self.cluster}'"
            )
        findings = parse_hardeneks(raw, account_id=account_id, region=region)
        # Tag each finding with its cluster so the consolidated report can group them.
        for f in findings:
            if not f.resource.startswith(self.cluster):
                f.resource = f"{self.cluster}/{f.resource}" if f.resource else self.cluster
        return ScanResult(self.name, ScanStatus.OK, findings=findings, raw=raw)


def _load_json(path: str):
    try:
        with open(path) as fh:
            return json.load(fh)
    except (json.JSONDecodeError, OSError):
        return None
