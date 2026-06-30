# ⬡ SentryHive

> Clone, point it at an AWS account, and get a clean security report from best-in-class open-source scanners — no manual tool wrangling.

SentryHive orchestrates several open-source AWS security scanners behind **one command** and merges their output into **one consolidated, severity-ranked report** (HTML + Markdown + JSON). No four-toolchain install nightmare, no four output formats to reconcile.

```bash
docker compose run --rm sentryhive scan --profile my-aws-profile
# → ./reports/report.html, report.md, findings.json
```

---

## Why

Running cloud security tools by hand means installing four toolchains, learning four CLIs, and reading four output formats. SentryHive does the wrangling for you:

1. **Zero-setup** — one Docker image bundles every scanner. You install nothing but Docker.
2. **Unified report** — every finding is normalized into one schema and one report.
3. **EKS coverage** — `hardeneks` integration is rare in aggregators.
4. **Trust-first** — ships a least-privilege IAM policy; **no data leaves your machine**.
5. **CI-native** — drop it into any pipeline as a security gate.

## Bundled scanners

| Tool | What it does | Target |
|------|--------------|--------|
| [Prowler](https://github.com/prowler-cloud/prowler) | 500+ checks across CIS, NIST, PCI, GDPR, HIPAA | live AWS account |
| [Cloudsplaining](https://github.com/salesforce/cloudsplaining) | IAM policy risk — over-privilege, priv-esc, exposure | live AWS account |
| [hardeneks](https://github.com/aws-samples/hardeneks) | EKS best-practice checks | live EKS cluster |
| [ASH](https://github.com/awslabs/automated-security-helper) | Static analysis of IaC/code (Terraform, CFN, secrets) | local files |

Prowler / Cloudsplaining / hardeneks scan a **live account**; ASH scans **code on disk**. Pick any subset with `--scanners`.

## Quick start (Docker — recommended)

```bash
git clone https://github.com/d2k-klin/sentryhive
cd sentryhive
docker compose build

# A) using an AWS profile (mounted read-only from ~/.aws)
docker compose run --rm sentryhive scan --profile my-aws-profile

# B) assume a role (cross-account supported)
docker compose run --rm sentryhive scan \
  --role-arn arn:aws:iam::123456789012:role/SentryHiveAudit

# C) pick scanners + regions
docker compose run --rm sentryhive scan --profile prod \
  --scanners prowler,cloudsplaining --regions eu-central-1,us-east-1
```

Reports appear in `./reports/`.

## Local install (pip)

The Python orchestrator installs from source; the underlying scanners must be on your `PATH` (or just use Docker, which bundles them).

```bash
pip install .
sentryhive scan --profile my-aws-profile
sentryhive scanners          # list available scanners
sentryhive --help
```

## Authentication

Resolved in priority order:

1. **Profile** — `--profile myprofile` (reads `~/.aws/credentials`)
2. **Static keys** — env `AWS_ACCESS_KEY_ID` / `AWS_SECRET_ACCESS_KEY` / `AWS_SESSION_TOKEN`
3. **Assume role** — `--role-arn ...` (+ optional `--external-id`, cross-account)

SentryHive always runs `sts:GetCallerIdentity` first and prints the account/identity it is about to scan, with a confirmation prompt unless you pass `--yes`.

### Least-privilege IAM

Grant only read-only audit access:

- [`iam/least-privilege-policy.json`](iam/least-privilege-policy.json) — attach alongside the AWS-managed `SecurityAudit` + `ViewOnlyAccess` policies.
- [`iam/audit-role.cfn.yaml`](iam/audit-role.cfn.yaml) — one-click CloudFormation role (supports cross-account + external ID).

```bash
aws cloudformation deploy --template-file iam/audit-role.cfn.yaml \
  --stack-name sentryhive-audit --capabilities CAPABILITY_NAMED_IAM \
  --parameter-overrides TrustedPrincipalArn=arn:aws:iam::<YOU>:root
```

## CLI

```
sentryhive scan [OPTIONS]

  --profile TEXT          AWS profile name
  --role-arn TEXT         IAM role ARN to assume (STS)
  --external-id TEXT      External ID for role assumption
  --regions TEXT          Comma-separated regions (eu-central-1,us-east-1)
  --scanners TEXT         Which scanners to run (default: all)
  --eks-cluster TEXT      EKS cluster name for hardeneks
  --source-dir TEXT       Directory ASH scans (default: CWD)
  --out TEXT              Output directory (default: ./reports)
  --yes, -y               Skip confirmation prompt
  --fail-on TEXT          Exit non-zero if any finding >= severity (CI gate)
```

Exit codes: `0` success · `1` auth/all-scanners-failed · `2` bad arguments · `3` `--fail-on` threshold breached.

## Reports

Three artifacts per run:

- **`report.html`** — self-contained (inline CSS/JS), severity-colored, filterable by tool/severity/status/text, with an exec summary up top. See [`examples/sample-report.html`](examples/sample-report.html).
- **`report.md`** — for PR comments and CI artifacts.
- **`findings.json`** — machine-readable, the unified schema, for piping elsewhere.

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
AWS creds → CLI → auth (STS verify) → [Prowler│Cloudsplaining│hardeneks│ASH]
                                              ↓ each → normalized findings
                                       Aggregator (dedup + rank)
                                              ↓
                                  Report generator (HTML + MD + JSON)
```

Each scanner is wrapped behind a common `Scanner.run()` interface, so adding a fifth tool is one wrapper module + one registry entry.

## Development

```bash
python -m venv .venv && source .venv/bin/activate
pip install -e ".[dev]"
ruff check .
pytest
```

## License

[Apache-2.0](LICENSE).
