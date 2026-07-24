"""Shared kubeconfig and RBAC preflight for in-cluster scanners."""

from __future__ import annotations

import os
import shutil

from sentryhive.auth import AwsContext
from sentryhive.scanners.base import Scanner, session_env


class KubernetesAccessError(RuntimeError):
    """The selected cluster cannot be scanned with the current access."""


class KubernetesScanner(Scanner):
    requires_aws = True

    def __init__(self, cluster: str | None = None, kubeconfig: str | None = None):
        self.cluster = cluster or os.environ.get("SENTRYHIVE_EKS_CLUSTER")
        self.kubeconfig = kubeconfig or os.environ.get("KUBECONFIG")
        if self.cluster:
            self.name = f"{self.name}[{self.cluster}]"

    def prepare_access(self, ctx: AwsContext | None, out_dir: str) -> tuple[dict, str, str]:
        """Return child env, AWS region, and account after kubeconfig/RBAC checks."""
        if not self.cluster:
            raise KubernetesAccessError("no cluster specified (use --kubernetes --clusters ...)")

        env = session_env(ctx)
        regions = ctx.regions if ctx and ctx.regions else [os.environ.get("AWS_DEFAULT_REGION", "")]
        region = regions[0]
        account_id = ctx.identity.account_id if ctx else ""

        if self.kubeconfig and os.path.exists(self.kubeconfig):
            env["KUBECONFIG"] = self.kubeconfig
        else:
            kubeconfig = os.path.join(out_dir, "kubeconfig")
            env["KUBECONFIG"] = kubeconfig
            last_error = ""
            for candidate in regions:
                upd = self._exec(
                    [
                        "aws",
                        "eks",
                        "update-kubeconfig",
                        "--name",
                        self.cluster,
                        *(["--region", candidate] if candidate else []),
                    ],
                    env=env,
                    progress=True,
                    progress_label=f"{self.name} kubeconfig",
                )
                if upd.returncode == 0:
                    region = candidate
                    break
                last_error = upd.stderr.strip()[-300:]
            else:
                raise KubernetesAccessError(
                    f"could not configure kubeconfig for '{self.cluster}' "
                    f"in regions {', '.join(r for r in regions if r) or 'default'} "
                    f"(cluster not found or no eks:DescribeCluster): {last_error}"
                )

        ok, detail = self._preflight(env)
        if not ok:
            raise KubernetesAccessError(
                f"no in-cluster access to '{self.cluster}' ({detail}). "
                "Grant a read-only EKS access entry / RBAC binding — see docs/eks-access.md"
            )
        return env, region, account_id

    def _preflight(self, env: dict) -> tuple[bool, str]:
        if shutil.which("kubectl") is None:
            return False, "kubectl not on PATH"
        probe = self._exec(["kubectl", "auth", "can-i", "list", "pods", "-A"], env=env, timeout=60)
        answer = (probe.stdout or "").strip().lower()
        if probe.returncode == 0 and answer.startswith("yes"):
            return True, "ok"
        stderr = (probe.stderr or "").lower()
        if "refused" in stderr or "timeout" in stderr or "deadline exceeded" in stderr:
            return False, "API server unreachable (private endpoint? run from within the client VPC)"
        return False, "RBAC denies read access"
