# Usage

Task-oriented examples first, then the full flag reference.

Placeholders used throughout: `<role-arn>` = an IAM role ARN
(`arn:aws:iam::123456789012:role/SentryHiveAudit`), `<account-id>` = a 12-digit AWS
account ID. Examples use the obviously-fake `123456789012` — never paste real
credentials or ARNs into shared commands.

All examples below use the local CLI (`sentryhive ...`). With Docker, prefix with
`docker compose run --rm sentryhive ...`.

## Scan with a profile

```bash
sentryhive scan --profile my-aws-profile
```

## Scan by assuming a role (with external ID)

```bash
sentryhive scan --role-arn arn:aws:iam::123456789012:role/SentryHiveAudit \
                --external-id shared-secret
```

SentryHive prints the account and identity it resolved, then prompts to proceed
(skip with `--yes`).

## Scan multiple accounts

Repeat `--role-arn`. All account findings are combined into one report under
`reports/`, while each finding retains its account ID.

```bash
sentryhive scan \
  --role-arn arn:aws:iam::111111111111:role/SentryHiveAudit \
  --role-arn arn:aws:iam::222222222222:role/SentryHiveAudit \
  --external-id shared-secret --client-name "Acme Corp"
```

## Pick scanners and regions

```bash
sentryhive scan --profile prod \
  --scanners prowler,cloudsplaining,cloudfox,resilience \
  --regions eu-central-1,us-east-1
```

Backup thresholds are engagement-specific — set them to the client's stated objectives,
since a retention number is only a finding relative to a target:

```bash
sentryhive scan --profile prod --rpo-hours 4 --retention-days 90
```

Add local IaC scanning with ASH:

```bash
sentryhive scan --scanners ash --source-dir ./infra
```

## Choose whether Kubernetes is in scope

Kubernetes is off by default and makes no cluster API calls. Enable it explicitly to
run both HardenEKS and Kubescape. EKS needs in-cluster access — see
[EKS access](eks-access.md).

```bash
sentryhive scan --role-arn <role-arn> --kubernetes --clusters prod-eks \
                --kubeconfig ~/.kube/client-x

# Explicit account-only scope
sentryhive scan --profile prod --no-kubernetes
```

## Generate a branded client report (with PDF)

```bash
sentryhive scan --role-arn <role-arn> --external-id shared-secret \
  --client-name "Acme Corp" --logo ./acme-logo.png \
  --pdf
```

Produces `reports/report.pdf` with a cover page, page numbers, and a scope &
methodology page — the deliverable. See [Reports](reports.md).

## Run in CI as a pass/fail gate

```bash
sentryhive scan --role-arn <role-arn> --yes --fail-on high
echo "exit code: $?"   # 3 if any High+ failing finding exists
```

See [CI/CD](ci-cd.md) for the reusable GitHub Actions workflow.

## Command & flag reference

### `sentryhive scan`

| Flag | Default | Description |
|------|---------|-------------|
| `--profile` | — | AWS profile name. |
| `--role-arn` | — | IAM role ARN to assume (STS). Repeat for multi-account. |
| `--external-id` | — | External ID for role assumption. |
| `--regions` | session default | Comma-separated regions. |
| `--scanners` | `prowler,cloudsplaining,cloudfox,resilience` | Account scanners to run; add `ash` for local IaC. |
| `--rpo-hours` | `24` | Recovery point objective the resilience scanner judges backup cadence and freshness against. |
| `--retention-days` | `35` | Minimum acceptable backup retention. |
| `--kubernetes / --no-kubernetes` | off | Include/exclude EKS HardenEKS + Kubescape checks. |
| `--clusters` | all detected | Comma-separated EKS clusters to target. |
| `--kubeconfig` | — | Path to a kubeconfig for EKS access. |
| `--source-dir` | CWD | Directory ASH scans. |
| `--client-name` | — | Client/engagement name in the report header. |
| `--logo` | — | Path to a logo image embedded in the report. |
| `--format` | `html,md,json` | Output formats: `html`, `md`, `json`, `pdf`. |
| `--pdf` | off | Shorthand to add PDF output. |
| `--pdf-engine` | `weasyprint` | `weasyprint` or `chromium`. |
| `--out` | `./reports` | Output directory. |
| `--yes`, `-y` | off | Skip the confirmation prompt. |
| `--fail-on` | — | Exit non-zero if any finding ≥ severity (`critical`/`high`/`medium`/`low`). |
| `--scanner-output` | off | Stream raw scanner stdout/stderr while commands run. Elapsed-time heartbeats are shown by default. |

### Other commands

| Command | Description |
|---------|-------------|
| `sentryhive scanners` | List available scanners and their roles. |
| `sentryhive --version` | Print the version. |
| `sentryhive --help` | Show help (works on any subcommand). |

### Exit codes

| Code | Meaning |
|------|---------|
| `0` | Success. |
| `1` | Authentication failure, or a selected scanner failed. Reports are still written when scanner execution fails. |
| `2` | Bad arguments (unknown scanner/format). |
| `3` | `--fail-on` threshold breached. |

> The flag table is kept in sync with the Typer definitions in
> [`sentryhive/cli.py`](../sentryhive/cli.py); `sentryhive scan --help` is always authoritative.
