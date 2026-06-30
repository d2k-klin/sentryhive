"""hardeneks scanner wrapper — EKS best-practice checks.

Requires a kubeconfig pointing at the target cluster. SentryHive will attempt to
generate one via `aws eks update-kubeconfig` when a cluster name is provided.
"""

from __future__ import annotations

import json
import os

from sentryhive.auth import AwsContext
from sentryhive.normalize import parse_hardeneks
from sentryhive.scanners.base import Scanner, ScanResult, ScanStatus, session_env


class HardeneksScanner(Scanner):
    name = "hardeneks"
    binary = "hardeneks"
    requires_aws = True

    def __init__(self, cluster: str | None = None):
        self.cluster = cluster or os.environ.get("SENTRYHIVE_EKS_CLUSTER")

    def _scan(self, ctx: AwsContext | None, workdir: str) -> ScanResult:
        if not self.cluster:
            return ScanResult(
                self.name, ScanStatus.SKIPPED,
                message="no EKS cluster specified (use --eks-cluster); skipping EKS checks.",
            )
        out_dir = os.path.join(workdir, "hardeneks")
        os.makedirs(out_dir, exist_ok=True)
        env = session_env(ctx)
        region = ctx.regions[0] if ctx and ctx.regions else os.environ.get("AWS_DEFAULT_REGION", "")
        account_id = ctx.identity.account_id if ctx else ""

        # Point kubectl/hardeneks at the cluster.
        kubeconfig = os.path.join(out_dir, "kubeconfig")
        env["KUBECONFIG"] = kubeconfig
        upd = self._exec(
            ["aws", "eks", "update-kubeconfig", "--name", self.cluster,
             *(["--region", region] if region else [])],
            env=env,
        )
        if upd.returncode != 0:
            return ScanResult(
                self.name, ScanStatus.ERROR,
                message=f"could not configure kubeconfig for '{self.cluster}': {upd.stderr[-400:]}",
            )

        export = os.path.join(out_dir, "hardeneks.json")
        self._exec(
            ["hardeneks", "--export-json", export, "--region", region or "us-east-1"],
            env=env,
        )
        raw = _load_json(export)
        if raw is None:
            return ScanResult(self.name, ScanStatus.ERROR,
                              message="hardeneks produced no JSON output")
        findings = parse_hardeneks(raw, account_id=account_id, region=region)
        return ScanResult(self.name, ScanStatus.OK, findings=findings, raw=raw)


def _load_json(path: str):
    try:
        with open(path) as fh:
            return json.load(fh)
    except (json.JSONDecodeError, OSError):
        return None
