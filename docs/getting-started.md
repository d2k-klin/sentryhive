# Getting started

Get from zero to a real report in under five minutes. This is a single happy path;
optional variations live in the [how-to guides](usage.md).

## Prerequisites

- [Docker](https://docs.docker.com/get-docker/) installed.
- An AWS account (or role) **you are authorized to scan**, and read-only credentials
  for it. A sandbox account is ideal for a first run.

> Only scan accounts you are authorized to scan.

## Step 1 — Get SentryHive

```bash
git clone https://github.com/d2k-klin/sentryhive
cd sentryhive
docker compose build
```

## Step 2 — Provide credentials

The simplest path is an AWS profile in `~/.aws/credentials`. `docker-compose.yml`
mounts `~/.aws` into the container read-only, so an existing profile just works.

```bash
# Verify you have a profile (this lists configured profiles)
aws configure list-profiles
```

## Step 3 — Run your first scan

```bash
docker compose run --rm sentryhive scan --profile my-aws-profile --yes
```

You'll see each scanner run, then a severity summary and a compliance posture table.
Expected output (abbreviated):

```
── Account 123456789012 ──
▶ running prowler …
  ok (212 findings)
▶ running cloudsplaining …
  ok (8 findings)
Findings by severity — 123456789012
 Critical  3
 High      11
 ...
Reports written:
  • html: ./reports/report.html
```

## Step 4 — Open your report

```bash
open ./reports/report.html      # macOS
# xdg-open ./reports/report.html  # Linux
```

Start with the **exec summary** at the top: severity counts, compliance posture per
framework, and the IAM privilege-escalation highlights. Then scroll to **All findings**
and filter by severity or tool.

## Next steps

- Scan a client account by [assuming a role](authentication.md#assume-role).
- Scan [multiple accounts at once](usage.md#scan-multiple-accounts).
- Produce a branded [PDF deliverable](reports.md#pdf) with `--pdf --client-name "Acme Corp"`.
- Add SentryHive to [CI as a gate](ci-cd.md).
