# ⬡ SentryHive

> Point it at a client's AWS account and get an evidence-grade security report from best-in-class open-source scanners — no manual tool wrangling.

[![CI](https://github.com/d2k-klin/sentryhive/actions/workflows/ci.yml/badge.svg)](https://github.com/d2k-klin/sentryhive/actions/workflows/ci.yml)
[![License: Apache-2.0](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](LICENSE)
[![Python 3.10+](https://img.shields.io/badge/python-3.10%2B-blue.svg)](pyproject.toml)
[![Docs](https://img.shields.io/badge/docs-docs%2F-blue.svg)](docs/index.md)
[![Read-only](https://img.shields.io/badge/AWS-read--only-green.svg)](docs/iam-permissions.md)

SentryHive is built for **security consultants and auditors**. It orchestrates several open-source AWS and Kubernetes security scanners behind **one command** and merges their output into **one consolidated, evidence-grade report** (branded HTML + Markdown + JSON) you can hand a client as a deliverable.

```bash
docker compose run --rm sentryhive scan \
  --role-arn arn:aws:iam::CLIENT:role/SentryHiveAudit \
  --external-id shared-secret --client-name "Acme Corp"
# → ./reports/report.html (branded), report.md, findings.json
```

ScoutSuite — historically the go-to for a single portable HTML audit report — has been effectively unmaintained since May 2024, and Prowler's raw output isn't reporting-friendly. SentryHive's wedge: **Prowler-grade coverage + Cloudsplaining IAM risk, delivered as the clean, branded, evidence-grade report ScoutSuite users are now missing.**

---

## Why

1. **Zero-setup** — one Docker image bundles every scanner. You install nothing but Docker.
2. **Evidence-grade report** — branded, self-contained HTML with scan metadata, compliance posture per framework, and the IAM privilege-escalation takeover narrative front and center.
3. **Cross-account first** — assume-role with `--external-id` is the primary path; scan **many client accounts in one run** and receive one engagement-wide report.
4. **Trust-first** — ships least-privilege IAM (CFN + Terraform) for the client to deploy; **no data leaves your machine**.
5. **CI-native** — drop it into any pipeline as a security gate.

## Bundled scanners

| Tool | What it does | Role |
|------|--------------|------|
| [Prowler](https://github.com/prowler-cloud/prowler) | 500+ checks mapped to CIS, PCI-DSS, SOC2, ISO-27001, HIPAA, NIST 800-53 | **core** |
| [Cloudsplaining](https://github.com/salesforce/cloudsplaining) | IAM policy risk — over-privilege, priv-esc, exposure | **core** |
| [CloudFox](https://github.com/BishopFox/cloudfox) | AWS attack surface, public exposure, role trusts, admin workloads | **core** |
| [hardeneks](https://github.com/aws-samples/hardeneks) | AWS EKS best-practice checks | opt-in (`--kubernetes`) |
| [Kubescape](https://github.com/kubescape/kubescape) | Kubernetes posture and misconfiguration controls | opt-in (`--kubernetes`) |
| [ASH](https://github.com/awslabs/automated-security-helper) | Static analysis of IaC/code (Terraform, CFN, secrets) | opt-in (`--scanners ...,ash`) |

The default scan runs **Prowler + Cloudsplaining + CloudFox**. Kubernetes is an
explicit choice: pass `--kubernetes` to run both HardenEKS and Kubescape, or
`--no-kubernetes` to make the account-only scope explicit. ASH scans local code/IaC
and is opt-in.

## Quick start (Docker — recommended)

```bash
git clone https://github.com/d2k-klin/sentryhive
cd sentryhive
docker compose build

# Primary path: assume a read-only audit role in the client account
docker compose run --rm sentryhive scan \
  --role-arn arn:aws:iam::123456789012:role/SentryHiveAudit \
  --external-id shared-secret --client-name "Acme Corp"

# Multi-account engagement: one combined report
docker compose run --rm sentryhive scan \
  --role-arn arn:aws:iam::111111111111:role/SentryHiveAudit \
  --role-arn arn:aws:iam::222222222222:role/SentryHiveAudit \
  --external-id shared-secret --client-name "Acme Corp"

# Or a local profile, picking scanners + regions
docker compose run --rm sentryhive scan --profile prod \
  --scanners prowler,cloudsplaining,cloudfox --regions eu-central-1,us-east-1
```

Every run writes one artifact set to `./reports/`: `report.html`, `report.md`, and
`findings.json` (plus `report.pdf` when requested). Multi-account, Kubernetes, and
ASH evidence are sections in that same report.

## Local install (pip)

The Python orchestrator installs from source; the underlying scanners must be on your `PATH` (or just use Docker, which bundles them).

```bash
pip install .
sentryhive scan --profile my-aws-profile
sentryhive scanners          # list available scanners
sentryhive --help
```

## Authentication: credentials versus roles

You always need a valid AWS credential source. You do **not** always need a role:

- **Scanning the account your credentials already belong to:** a profile, environment
  keys, EC2/ECS task role, or CI workload credentials are sufficient if that principal
  has the documented read permissions. Do not add `--role-arn`.
- **Scanning a client/cross-account target:** the base credentials also need
  `sts:AssumeRole` permission, and the client deploys a trusted audit role. Pass its
  ARN with `--role-arn`; add `--external-id` when the trust policy requires it.
- **Kubernetes/EKS:** add `--kubernetes`. If SentryHive creates the kubeconfig, the AWS
  principal needs `eks:DescribeCluster`; either way it also needs Kubernetes RBAC and
  network reachability to the cluster API. SentryHive still requires an AWS credential
  source for its verified AWS/EKS context even when you provide `--kubeconfig`.

SentryHive runs `sts:GetCallerIdentity` per account and prints the account/identity it is about to scan, with a confirmation prompt unless you pass `--yes`.

### Client onboarding — least-privilege audit role

Hand the **client** a template to deploy a read-only role that trusts your account (+ external ID). Both flavors are shipped:

- [`iam/audit-role.cfn.yaml`](iam/audit-role.cfn.yaml) — CloudFormation
- [`iam/audit-role.tf`](iam/audit-role.tf) — Terraform
- [`iam/least-privilege-policy.json`](iam/least-privilege-policy.json) — the raw policy (attach alongside AWS-managed `SecurityAudit` + `ViewOnlyAccess`)

```bash
# Client runs this in their account:
aws cloudformation deploy --template-file iam/audit-role.cfn.yaml \
  --stack-name sentryhive-audit --capabilities CAPABILITY_NAMED_IAM \
  --parameter-overrides TrustedPrincipalArn=arn:aws:iam::<CONSULTANT>:root \
                        ExternalId=<shared-secret>
# Then hands you the role ARN → sentryhive scan --role-arn <arn> --external-id <shared-secret>
```

## CLI

```
sentryhive scan [OPTIONS]

  --role-arn TEXT         IAM role ARN to assume (STS). Repeat for multi-account.
  --external-id TEXT      External ID for role assumption
  --profile TEXT          AWS profile name
  --regions TEXT          Comma-separated regions (eu-central-1,us-east-1)
  --scanners TEXT         Account scanners (default: prowler,cloudsplaining,cloudfox)
  --kubernetes / --no-kubernetes
                          Include/exclude EKS checks (HardenEKS + Kubescape)
  --clusters TEXT         EKS clusters to target (default: all detected)
  --kubeconfig PATH       kubeconfig for EKS access
  --source-dir TEXT       Directory ASH scans (default: CWD)
  --client-name TEXT      Client/engagement name for the report header
  --logo PATH             Logo image embedded in the report header
  --format TEXT           Output formats: html,md,json,pdf (default: html,md,json)
  --pdf                   Shorthand to add PDF output
  --pdf-engine TEXT       weasyprint (default) or chromium
  --out TEXT              Output directory (default: ./reports)
  --yes, -y               Skip confirmation prompt
  --fail-on TEXT          Exit non-zero if any finding >= severity (CI gate)
  --scanner-output        Stream raw scanner output; heartbeats are shown by default
```

> Kubernetes assessment is a **separate, opt-in phase** because it needs
> in-cluster RBAC and API-server network access. With `--no-kubernetes` (the
> default), SentryHive does not enumerate or connect to clusters. See
> [docs/eks-access.md](docs/eks-access.md).

Exit codes: `0` success · `1` authentication or scanner failure · `2` bad arguments ·
`3` `--fail-on` threshold breached.

## Reports — the deliverable

Per scan:

- **`report.html`** — self-contained, **client-branded** (`--client-name`, `--logo`), fail-first and filterable. It combines account, attack-surface, Kubernetes, and optional source findings; pass evidence and observations remain available without inflating risk totals.
- **`report.pdf`** — the client deliverable: dated, page-numbered, branded, with a cover page and a scope & methodology page. Add with `--pdf`. Rendered locally via WeasyPrint (no browser, no network). See [`examples/sample-report.pdf`](examples/sample-report.pdf) and [docs/reports.md](docs/reports.md).
- **`report.md`** — for PR comments and CI artifacts.
- **`findings.json`** — machine-readable, the unified schema, for piping elsewhere.

Every run produces exactly one report set. Findings preserve `account_id`, tool, region,
and cluster/resource context so the unified register remains traceable.

### Unified finding schema

Every scanner normalizes into this shape (`sentryhive/models.py`):

```json
{
  "id": "a1b2c3d4e5f6",
  "tool": "prowler",
  "check": "s3_bucket_public_access",
  "title": "S3 bucket allows public access",
  "severity": "Critical",
  "severity_rank": 4,
  "resource": "arn:aws:s3:::acme-prod-assets",
  "service": "s3",
  "region": "us-east-1",
  "status": "fail",
  "remediation": "Enable S3 Block Public Access ...",
  "compliance_refs": ["CIS:2.1.5", "NIST:SC-7"],
  "account_id": "123456789012"
}
```

When two tools flag the same `service + resource + check`, findings are **deduped** to the highest-severity instance and tagged `flagged-by:tool-a+tool-b`.

## CI/CD

A reusable workflow lives at [`.github/workflows/scan-example.yml`](.github/workflows/scan-example.yml). It assumes a role via OIDC, runs the scan, uploads the report as an artifact, and posts the Markdown summary as a PR comment. Use `--fail-on high` to gate merges.

## Architecture

```
AWS creds → CLI → auth (STS verify) → [Prowler│Cloudsplaining│CloudFox]
Kubernetes choice + RBAC ───────────→ [HardenEKS│Kubescape]
Local source (optional) ────────────→ [ASH]
                                              ↓ normalized findings
                                       Aggregator (dedup + rank + posture)
                                              ↓
                              Report generator (HTML + PDF + MD + JSON)
```

Each scanner is wrapped behind a common `Scanner.run()` interface, so adding another
tool is one wrapper module + one registry entry. Full write-up in
[docs/architecture.md](docs/architecture.md).

## Documentation

Full docs live in [`docs/`](docs/index.md):

| Start here | Auth & trust | Reference |
|------------|--------------|-----------|
| [Getting started](docs/getting-started.md) | [Authentication](docs/authentication.md) | [Usage & flags](docs/usage.md) |
| [Installation](docs/installation.md) | [IAM permissions](docs/iam-permissions.md) | [Scanners](docs/scanners.md) |
| [FAQ](docs/faq.md) | [EKS access](docs/eks-access.md) | [Reports](docs/reports.md) |
| [Troubleshooting](docs/troubleshooting.md) | [CI/CD](docs/ci-cd.md) | [Configuration](docs/configuration.md) |

## Security & trust

- **All scanning is read-only.** SentryHive performs no write, modify, or delete actions.
- **No data leaves your machine** — scanning *and* PDF generation run fully locally.
- Ships least-privilege IAM ([CloudFormation](iam/audit-role.cfn.yaml) / [Terraform](iam/audit-role.tf)) for clients to deploy.

Report a vulnerability via [SECURITY.md](SECURITY.md) (private disclosure — not a public issue).

## Contributing

Contributions welcome — see [CONTRIBUTING.md](CONTRIBUTING.md) (dev setup, how to add a scanner, PR checklist) and our [Code of Conduct](CODE_OF_CONDUCT.md). Changes are logged in [CHANGELOG.md](CHANGELOG.md).

```bash
python -m venv .venv && source .venv/bin/activate
pip install -e ".[dev,pdf]"
ruff check .
pytest
```

## License

[Apache-2.0](LICENSE).
