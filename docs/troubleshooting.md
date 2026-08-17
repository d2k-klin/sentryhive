# Troubleshooting

Symptom → likely cause → fix.

| Symptom | Likely cause | Fix |
|---------|--------------|-----|
| `Authentication failed: ... sts:GetCallerIdentity` | No/invalid credentials, or profile not found | Check `--profile`/keys; run `aws sts get-caller-identity` to confirm the base creds work. |
| `Failed to assume role ... AccessDenied` | Trust policy doesn't allow your principal, or wrong external ID | Verify the role's trust policy and pass the correct `--external-id`. See [IAM permissions](iam-permissions.md). |
| Assume-role works but scan shows many `AccessDenied` findings/errors | Role missing read permissions | Attach `SecurityAudit` + `ViewOnlyAccess` + the [extra policy](../iam/least-privilege-policy.json). |
| Scanner reported `skipped — '<tool>' not found on PATH` | Running from source without that tool | Install the tool, or use the Docker image which bundles all of them. |
| Scanner appears quiet for a long time | The underlying scanner is still running a large account scan | Wait for the elapsed-time heartbeat; re-run with `--scanner-output` to stream raw scanner logs. |
| Report shows `0 findings` with scanner status `error` / exit code `1` | One or more scanners failed or timed out before producing parseable output | Treat the report as incomplete evidence. Re-run the failed scanner with `--scanner-output`; for Prowler, narrow scope with `--regions` or `--scanners prowler` while debugging. |
| `--kubernetes` run: cluster `skipped — no in-cluster access` | Missing Kubernetes RBAC grant | Apply the [EKS access](eks-access.md) onboarding (access entry + RBAC). |
| `--kubernetes` run: `API server unreachable (private endpoint?)` | Cluster has a private-only API endpoint | Run from within the client VPC (VPN/bastion/in-VPC runner). |
| `--kubernetes` requested but `no EKS clusters found` | No clusters, wrong region, or missing `eks:ListClusters` | Add `--regions`; confirm clusters exist with `aws eks list-clusters`. |
| `PDF generation skipped: WeasyPrint is not available` | WeasyPrint or pango/cairo missing | Use Docker, or `pip install "sentryhive[pdf]"` + system libs (`brew install pango` / `apt-get install libpango-1.0-0 libcairo2`). |
| `--pdf-engine chromium`: `no Chromium/Chrome binary found` | No Chromium on PATH | Install Chromium, or use the default `weasyprint` engine. |
| Wrong/empty region results | Region not set | Pass `--regions`, or set `AWS_DEFAULT_REGION`. |
| `Unknown scanner(s)` / `Unknown format(s)` | Typo in `--scanners`/`--format` | Valid scanners: `prowler,cloudsplaining,cloudfox,resilience,hardeneks,kubescape,ash`. Valid formats: `html,md,json,pdf`. |
| `cloudfox — ... error unmarshalling YAML` | Upstream defect in CloudFox 2.0.5: it parses IAM policy JSON with a YAML unmarshaller, so valid JSON that is not valid YAML aborts the module | Not fixable from SentryHive and no fixed CloudFox release exists. Compliance/IAM/backup evidence is unaffected; re-run with `--scanners prowler,cloudsplaining,resilience` for a clean exit. |
| `cloudfox — ... crashed — killed by SIGSEGV` | CloudFox segfaulted. Most often seen running the amd64 image emulated on Apple Silicon | Same as above. If you are on arm64, try a natively built image (`docker compose build`) before assuming the account data is at fault. |
| Exit code `1` with a full report and thousands of findings | A scanner could not finish, so evidence is incomplete — not that findings were found | Read the scanner's message: it names the cause and whether it is yours to fix. Findings alone never fail a run. |
| Exit code `3` in CI | `--fail-on` threshold breached | Expected — findings at/above the threshold exist. Review the report. |
| Docker: `--profile` ignored | `~/.aws` not mounted | Use the provided `docker-compose.yml`, or mount `-v ~/.aws:/root/.aws:ro`. |

## Getting more detail

- `sentryhive scan --help` — authoritative flag reference.
- Re-run a single scanner to isolate the problem: `--scanners prowler`.
- Add `--scanner-output` when you need raw scanner logs in the terminal.
- Inspect `findings.json` for the raw normalized output.

Still stuck? Open an issue with the bug-report template (include SentryHive version,
scanner versions, OS, and a **sanitized** command — never paste credentials or real
ARNs).
