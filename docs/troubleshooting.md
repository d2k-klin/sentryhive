# Troubleshooting

Symptom → likely cause → fix.

| Symptom | Likely cause | Fix |
|---------|--------------|-----|
| `Authentication failed: ... sts:GetCallerIdentity` | No/invalid credentials, or profile not found | Check `--profile`/keys; run `aws sts get-caller-identity` to confirm the base creds work. |
| `Failed to assume role ... AccessDenied` | Trust policy doesn't allow your principal, or wrong external ID | Verify the role's trust policy and pass the correct `--external-id`. See [IAM permissions](iam-permissions.md). |
| Assume-role works but scan shows many `AccessDenied` findings/errors | Role missing read permissions | Attach `SecurityAudit` + `ViewOnlyAccess` + the [extra policy](../iam/least-privilege-policy.json). |
| Scanner reported `skipped — '<tool>' not found on PATH` | Running from source without that tool | Install the tool, or use the Docker image which bundles all of them. |
| `--eks` run: cluster `skipped — no in-cluster access` | Missing Kubernetes RBAC grant | Apply the [EKS access](eks-access.md) onboarding (access entry + RBAC). |
| `--eks` run: `API server unreachable (private endpoint?)` | Cluster has a private-only API endpoint | Run from within the client VPC (VPN/bastion/in-VPC runner). |
| `--eks` requested but `no EKS clusters found` | No clusters, or wrong region | Add `--regions`; confirm clusters exist with `aws eks list-clusters`. |
| `PDF generation skipped: WeasyPrint is not available` | WeasyPrint or pango/cairo missing | Use Docker, or `pip install "sentryhive[pdf]"` + system libs (`brew install pango` / `apt-get install libpango-1.0-0 libcairo2`). |
| `--pdf-engine chromium`: `no Chromium/Chrome binary found` | No Chromium on PATH | Install Chromium, or use the default `weasyprint` engine. |
| Wrong/empty region results | Region not set | Pass `--regions`, or set `AWS_DEFAULT_REGION`. |
| `Unknown scanner(s)` / `Unknown format(s)` | Typo in `--scanners`/`--format` | Valid scanners: `prowler,cloudsplaining,hardeneks,ash`. Valid formats: `html,md,json,pdf`. |
| Exit code `3` in CI | `--fail-on` threshold breached | Expected — findings at/above the threshold exist. Review the report. |
| Docker: `--profile` ignored | `~/.aws` not mounted | Use the provided `docker-compose.yml`, or mount `-v ~/.aws:/root/.aws:ro`. |

## Getting more detail

- `sentryhive scan --help` — authoritative flag reference.
- Re-run a single scanner to isolate the problem: `--scanners prowler`.
- Inspect `findings.json` for the raw normalized output.

Still stuck? Open an issue with the bug-report template (include SentryHive version,
scanner versions, OS, and a **sanitized** command — never paste credentials or real
ARNs).
