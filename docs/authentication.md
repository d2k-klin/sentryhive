# Authentication

SentryHive supports three credential modes. For the consultant workflow,
**assume-role is the primary path**.

## Precedence order

1. **Assume role** — `--role-arn` (+ optional `--external-id`). Repeat for multiple accounts.
2. **Profile** — `--profile <name>` (reads `~/.aws/credentials`).
3. **Static keys** — the standard `AWS_ACCESS_KEY_ID` / `AWS_SECRET_ACCESS_KEY` /
   `AWS_SESSION_TOKEN` environment variables.

A profile (or ambient env keys) establishes the base session. When `--role-arn` is
given, that base session assumes the role via STS and a new session is built from the
temporary credentials.

## Identity verification

Before scanning, SentryHive calls `sts:GetCallerIdentity` for each target account and
prints the account ID and identity ARN, then prompts to proceed (skip with `--yes`).
This is your confirmation that you're pointed at the right account.

## Assume role

```bash
sentryhive scan \
  --role-arn arn:aws:iam::123456789012:role/SentryHiveAudit \
  --external-id shared-secret
```

### External ID

When a client grants a third party (you) access, AWS best practice is to require an
**external ID** — a shared secret that must be presented on `sts:AssumeRole`. Pass it
with `--external-id`. The client sets the matching condition in the role's trust
policy (the shipped [onboarding templates](iam-permissions.md) do this for you).

### Cross-account / multi-account

Repeat `--role-arn` to scan several client accounts in one run. The same
`--external-id` applies to all of them.

```bash
sentryhive scan \
  --role-arn arn:aws:iam::111111111111:role/SentryHiveAudit \
  --role-arn arn:aws:iam::222222222222:role/SentryHiveAudit \
  --external-id shared-secret
```

## Profile

```bash
sentryhive scan --profile client-x
```

With Docker, `~/.aws` is mounted read-only so profiles work transparently.

## Static keys

```bash
export AWS_ACCESS_KEY_ID=AKIA...
export AWS_SECRET_ACCESS_KEY=...
export AWS_SESSION_TOKEN=...      # if using temporary credentials
sentryhive scan
```

## Session duration

Assumed-role sessions use the role's default duration. For very large accounts, set a
longer `MaxSessionDuration` on the role (the shipped CFN/TF default is 3600s) so a
scan doesn't outlast its credentials.

## Credentials never leave your machine

SentryHive resolves credentials in-process and passes them to the bundled scanners
via environment variables for the duration of the run only. They are never written to
the report or persisted by SentryHive. See [SECURITY.md](../SECURITY.md).
