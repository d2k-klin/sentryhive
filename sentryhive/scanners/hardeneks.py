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
from sentryhive.scanners.base import Scanner, ScanResult, ScanStatus, session_env


class HardeneksScanner(Scanner):
    name = "hardeneks"
    binary = "hardeneks"
    requires_aws = True

    def __init__(self, cluster: str | None = None, kubeconfig: str | None = None):
        self.cluster = cluster or os.environ.get("SENTRYHIVE_EKS_CLUSTER")
        self.kubeconfig = kubeconfig or os.environ.get("KUBECONFIG")
        if self.cluster:
            self.name = f"hardeneks[{self.cluster}]"

    def _scan(self, ctx: AwsContext | None, workdir: str) -> ScanResult:
        if not self.cluster:
            return ScanResult(
                self.name,
                ScanStatus.SKIPPED,
                message="no EKS cluster specified (use --eks --clusters ...).",
            )
        safe = self.cluster.replace("/", "_")
        out_dir = os.path.join(workdir, f"hardeneks-{safe}")
        os.makedirs(out_dir, exist_ok=True)
        env = session_env(ctx)
        region = ctx.regions[0] if ctx and ctx.regions else os.environ.get("AWS_DEFAULT_REGION", "")
        account_id = ctx.identity.account_id if ctx else ""

        # Use a provided kubeconfig as-is; otherwise generate one for this cluster.
        if self.kubeconfig and os.path.exists(self.kubeconfig):
            env["KUBECONFIG"] = self.kubeconfig
        else:
            kubeconfig = os.path.join(out_dir, "kubeconfig")
            env["KUBECONFIG"] = kubeconfig
            upd = self._exec(
                ["aws", "eks", "update-kubeconfig", "--name", self.cluster, *(["--region", region] if region else [])],
                env=env,
                progress=True,
                progress_label=f"{self.name} kubeconfig",
            )
            if upd.returncode != 0:
                return ScanResult(
                    self.name,
                    ScanStatus.SKIPPED,
                    message=f"could not configure kubeconfig for '{self.cluster}' "
                    f"(cluster not found or no eks:DescribeCluster): {upd.stderr.strip()[-300:]}",
                )

        # Preflight: confirm we actually have in-cluster read access before scanning.
        ok, detail = self._preflight(env)
        if not ok:
            return ScanResult(
                self.name,
                ScanStatus.SKIPPED,
                message=f"no in-cluster access to '{self.cluster}' ({detail}). "
                "Grant a read-only EKS access entry / RBAC binding — see docs/eks-access.md.",
            )

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

    def _preflight(self, env: dict) -> tuple[bool, str]:
        """`kubectl auth can-i` probe. Returns (ok, detail).

        A private-only API-server endpoint or a missing RBAC grant both surface here
        as a failed probe, which we translate into a graceful per-cluster skip.
        """
        import shutil

        if shutil.which("kubectl") is None:
            return False, "kubectl not on PATH"
        probe = self._exec(["kubectl", "auth", "can-i", "list", "pods", "-A"], env=env, timeout=60)
        answer = (probe.stdout or "").strip().lower()
        if probe.returncode == 0 and answer.startswith("yes"):
            return True, "ok"
        if "refused" in (probe.stderr or "").lower() or "timeout" in (probe.stderr or "").lower():
            return False, "API server unreachable (private endpoint? run from within the client VPC)"
        return False, "RBAC denies read access"


def _load_json(path: str):
    try:
        with open(path) as fh:
            return json.load(fh)
    except (json.JSONDecodeError, OSError):
        return None
