# CI/CD

Run SentryHive in a pipeline as a security gate. The repo ships a reusable GitHub
Actions workflow at
[`.github/workflows/scan-example.yml`](../.github/workflows/scan-example.yml).

## Reusable workflow

It assumes a role via OIDC, runs the scan in the Docker image, uploads the report as
an artifact, and (on PRs) posts the Markdown summary as a comment.

```yaml
jobs:
  security:
    uses: d2k-klin/sentryhive/.github/workflows/scan-example.yml@main
    permissions:
      id-token: write     # OIDC role assumption
      contents: read
      pull-requests: write
    with:
      role-arn: arn:aws:iam::123456789012:role/SentryHiveAudit
      regions: eu-central-1,us-east-1
      scanners: prowler,cloudsplaining
      fail-on: high
```

### Inputs

| Input | Default | Purpose |
|-------|---------|---------|
| `role-arn` | required | Role assumed via OIDC. |
| `regions` | `us-east-1` | Comma-separated regions. |
| `scanners` | `prowler,cloudsplaining` | Scanners to run. |
| `fail-on` | `""` | Fail the job at/above this severity. |

## Using OIDC

Configure the audit role's trust policy to trust GitHub's OIDC provider so no
long-lived keys are stored in CI. See AWS's
[configure-aws-credentials](https://github.com/aws-actions/configure-aws-credentials)
action and the role template in [iam-permissions.md](iam-permissions.md).

## Exit-code gating

`--fail-on <severity>` makes `sentryhive scan` exit `3` when any failing finding at or
above that severity exists. Use it to block merges:

```bash
sentryhive scan --role-arn "$AUDIT_ROLE_ARN" --yes --fail-on high
```

Full exit-code table: [usage.md](usage.md#exit-codes).

## Artifacts & PR comments

The workflow uploads `reports/` (HTML/MD/JSON, and PDF if enabled) as a build
artifact, and posts `report.md` as a PR comment (truncated if very large). Add `--pdf`
to the run command if you want the PDF deliverable attached to every build.

## Running the raw image

Any CI system can run the image directly:

```bash
docker run --rm \
  -e AWS_ACCESS_KEY_ID -e AWS_SECRET_ACCESS_KEY -e AWS_SESSION_TOKEN -e AWS_DEFAULT_REGION \
  -v "$PWD/reports:/app/reports" \
  ghcr.io/d2k-klin/sentryhive:latest \
  scan --yes --fail-on high --out /app/reports
```
