# IAM permissions

SentryHive needs **read-only** access. This page documents exactly what, and gives the
client a copy-pasteable onboarding template. This is a trust document — read it
before pointing the tool at any account.

## What SentryHive needs

Account-level scanning (Prowler + Cloudsplaining) is covered by the AWS-managed
**`SecurityAudit`** and **`ViewOnlyAccess`** policies, plus a handful of extra
read-only actions:

- `sts:GetCallerIdentity` — identity verification.
- `iam:GetAccountAuthorizationDetails`, `iam:GenerateCredentialReport`,
  `iam:GetCredentialReport` — IAM policy analysis (Cloudsplaining) and IAM checks.
- `eks:ListClusters` / `eks:DescribeCluster` (+ nodegroup/addon list/describe) — EKS
  detection and metadata.

No write, modify, or delete actions are requested. The full policy is shipped at
[`iam/least-privilege-policy.json`](../iam/least-privilege-policy.json).

> **EKS hardening (`--eks`) needs more.** Reading *inside* a cluster requires an extra
> in-cluster RBAC grant per cluster — see [EKS access](eks-access.md). Account-level
> scanning does not.

## Client onboarding — the audit role

Hand the client one of these to deploy a read-only role that trusts your account with
an external ID.

### CloudFormation

```bash
aws cloudformation deploy --template-file iam/audit-role.cfn.yaml \
  --stack-name sentryhive-audit --capabilities CAPABILITY_NAMED_IAM \
  --parameter-overrides \
    TrustedPrincipalArn=arn:aws:iam::<CONSULTANT_ACCOUNT_ID>:root \
    ExternalId=<shared-secret>
```

Template: [`iam/audit-role.cfn.yaml`](../iam/audit-role.cfn.yaml). The output
`RoleArn` is what you pass to `--role-arn`.

### Terraform

```bash
terraform apply \
  -var 'trusted_principal_arn=arn:aws:iam::<CONSULTANT_ACCOUNT_ID>:root' \
  -var 'external_id=<shared-secret>'
```

Template: [`iam/audit-role.tf`](../iam/audit-role.tf). The `role_arn` output is what
you pass to `--role-arn`.

### Attach the raw policy instead

If the client prefers to attach to an existing role, give them
[`iam/least-privilege-policy.json`](../iam/least-privilege-policy.json) alongside the
AWS-managed `SecurityAudit` and `ViewOnlyAccess` policies.

## Verifying

After onboarding, confirm access without scanning:

```bash
aws sts assume-role --role-arn <role-arn> --role-session-name test \
  --external-id <shared-secret>
```

If that returns credentials, SentryHive will work. If it fails, see
[Troubleshooting](troubleshooting.md).
