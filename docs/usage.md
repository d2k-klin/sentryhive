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

Repeat `--role-arn`. You get a report per account under `reports/<account-id>/` and a
cross-account roll-up at `reports/`.

```bash
sentryhive scan \
  --role-arn arn:aws:iam::111111111111:role/SentryHiveAudit \
  --role-arn arn:aws:iam::222222222222:role/SentryHiveAudit \
  --external-id shared-secret --client-name "Acme Corp"
```

## Pick scanners and regions

```bash
sentryhive scan --profile prod \
  --scanners prowler,cloudsplaining \
  --regions eu-central-1,us-east-1
```

Add local IaC scanning with ASH:

```bash
sentryhive scan --scanners ash --source-dir ./infra
```

## Run EKS hardening (opt-in)

EKS needs in-cluster access — see [EKS access](eks-access.md).

```bash
sentryhive scan --role-arn <role-arn> --eks --clusters prod-eks \
                --kubeconfig ~/.kube/client-x
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
| `--scanners` | `prowler,cloudsplaining` | Account scanners to run; add `ash` for local IaC. |
| `--eks` | off | Run EKS hardening (opt-in; needs in-cluster access). |
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
| `1` | Authentication failure. |
| `2` | Bad arguments (unknown scanner/format). |
| `3` | `--fail-on` threshold breached. |

> The flag table is kept in sync with the Typer definitions in
> [`sentryhive/cli.py`](../sentryhive/cli.py); `sentryhive scan --help` is always authoritative.
