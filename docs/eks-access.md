# EKS Hardening access (opt-in)

EKS hardening (`hardeneks`) is fundamentally different from the other scanners.

| | Prowler / Cloudsplaining | hardeneks |
|---|---|---|
| Data source | AWS API only | **Inside the Kubernetes cluster** |
| Access needed | Read-only **IAM** role | Read-only IAM role **+ in-cluster RBAC** per cluster |
| Works via assume-role alone? | ✅ Yes | ❌ No — needs an extra in-cluster grant |

**Account-level scanning works without any of this.** The default scan
(`prowler,cloudsplaining`) only needs the read-only IAM role from
[`audit-role.cfn.yaml`](../iam/audit-role.cfn.yaml). EKS hardening is a separate,
opt-in second phase you enable with `--eks`, and it requires the client to grant
the audit principal Kubernetes-level read access on **each** cluster.

## How SentryHive behaves

- **Default run:** SentryHive calls `eks:ListClusters` and, if clusters exist,
  *reports* them and notes that EKS hardening is available via `--eks`. It does
  **not** silently run hardeneks.
- **`--eks`:** runs the EKS phase against detected clusters (or `--clusters a,b`).
- **Preflight:** before scanning each cluster, SentryHive runs a
  `kubectl auth can-i list pods -A` probe. If access is missing (or the API server
  is unreachable), that cluster is **skipped gracefully** with an actionable
  message — the rest of the run continues.

```bash
# Account scan only (no EKS access required)
sentryhive scan --role-arn arn:aws:iam::<client>:role/SentryHiveAudit --external-id <id>

# Add EKS hardening (requires the grants below)
sentryhive scan --role-arn arn:aws:iam::<client>:role/SentryHiveAudit --external-id <id> \
  --eks --clusters prod-eks,staging-eks --kubeconfig ~/.kube/client-x
```

## Granting access (client side, per cluster)

Pick the path that matches the cluster's authentication mode.

### Option A — EKS access entries (modern, recommended)

1. Map the audit principal to a Kubernetes group:

   ```bash
   aws cloudformation deploy --template-file iam/eks-access.yaml \
     --stack-name sentryhive-eks-<cluster> \
     --parameter-overrides ClusterName=<cluster> \
       AuditPrincipalArn=arn:aws:iam::<client>:role/SentryHiveAudit
   ```

2. Bind that group to read-only RBAC inside the cluster:

   ```bash
   kubectl apply -f iam/eks-readonly-rbac.yaml
   ```

### Option B — aws-auth / RBAC (legacy clusters)

1. Add the audit principal to the `aws-auth` ConfigMap mapping it to the
   `sentryhive-readonly` group.
2. Apply [`iam/eks-readonly-rbac.yaml`](../iam/eks-readonly-rbac.yaml).

## Known limitations

- **Private API-server endpoints:** clusters with public access disabled can only
  be scanned from inside the client's network (VPN, bastion, or a runner in-VPC).
  SentryHive will report such clusters as "skipped — API server unreachable."
- **Partial access:** in a multi-cluster account, reachable clusters are scanned
  and the rest are reported as skipped; the run never aborts because one cluster is
  inaccessible.
