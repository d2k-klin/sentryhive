# Authentication

SentryHive supports the standard AWS credential chain plus optional role assumption.
The deciding question is whether the credentials already belong to the target account.

## Do I need a role?

| Situation | What you provide |
|---|---|
| Scan the AWS account your current principal belongs to | AWS credentials only: profile, environment variables, EC2/ECS role, or CI workload credentials |
| Scan a different/client AWS account | Base AWS credentials **plus** the client's `--role-arn`; add `--external-id` if its trust policy requires one |
| Scan EKS with `--kubernetes` and no supplied kubeconfig | The above AWS access with `eks:DescribeCluster`, plus in-cluster Kubernetes RBAC |
| Scan EKS with a working `--kubeconfig` | AWS credentials are still required for SentryHive's verified AWS/EKS context; the kubeconfig supplies cluster routing/auth configuration, not a replacement for AWS identity |

Credentials authenticate a principal; permissions determine what it can read. Static
access keys are not more capable than a profile or workload role, and SentryHive does
not require long-lived keys.

SentryHive is AWS/EKS-oriented, so every `scan` needs an AWS credential source even
when Kubernetes is the only selected phase. A working kubeconfig does not change the
role decision: use credentials directly for the same account, or assume the client's
audit role for cross-account work.

## Precedence order

1. **Profile** — `--profile <name>` (reads `~/.aws/credentials`).
2. **Environment/workload credentials** — the standard AWS SDK credential chain.
3. **Assume role** — when `--role-arn` is supplied, the resolved base credentials
   call STS and SentryHive uses the returned temporary role credentials.

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

Prefer temporary credentials. Never paste keys into a command, configuration file,
report, or support ticket.

## Session duration

Assumed-role sessions use the role's default duration. For very large accounts, set a
longer `MaxSessionDuration` on the role (the shipped CFN/TF default is 3600s) so a
scan doesn't outlast its credentials.

## Credentials never leave your machine

SentryHive resolves credentials in-process and passes them to the bundled scanners
via environment variables for the duration of the run only. They are never written to
the report or persisted by SentryHive. See [SECURITY.md](../SECURITY.md).
