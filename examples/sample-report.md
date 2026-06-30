# 🛡️ SentryHive Security Report

| | |
|---|---|
| **Account** | `123456789012` |
| **Identity** | `arn:aws:iam::123456789012:role/SentryHiveAudit` |
| **Regions** | us-east-1, eu-central-1 |
| **Generated** | 2026-06-30 12:00:00 UTC |
| **Total findings** | 11 |

## Summary by severity

| Severity | Count |
|----------|-------|
| Critical | 2 |
| High | 5 |
| Medium | 3 |
| Low | 0 |
| Info | 1 |

**Status:** 10 fail · 1 pass · 0 info
**Services covered:** checkov, cloudtrail, detect-secrets, ec2, eks, iam, rds, s3

## Scanners

| Scanner | Status | Findings | Notes |
|---------|--------|----------|-------|
| prowler | ok | 5 |  |
| cloudsplaining | ok | 2 |  |
| hardeneks | ok | 2 |  |
| ash | ok | 2 |  |

## Top 10 risks

| # | Severity | Tool | Resource | Check |
|---|----------|------|----------|-------|
| 1 | Critical | prowler | `root` | Root account has no MFA |
| 2 | Critical | prowler | `arn:aws:s3:::acme-prod-assets` | S3 bucket allows public access |
| 3 | High | ash | `app/config.py:42` | Hardcoded AWS access key in source |
| 4 | High | cloudsplaining | `DeployRole` | Privilege escalation path: DeployRole |
| 5 | High | cloudsplaining | `BackupRole` | Resource exposure: BackupRole |
| 6 | High | hardeneks | `prod-cluster/kube-system` | Anonymous access bound to cluster role |
| 7 | High | prowler | `sg-0a1b2c3d` | Security group exposes SSH to 0.0.0.0/0 |
| 8 | Medium | ash | `terraform/s3.tf:14` | S3 bucket has no access logging |
| 9 | Medium | hardeneks | `prod-cluster/default` | Wildcards used in Role rules |
| 10 | Medium | prowler | `account` | CloudTrail not enabled in all regions |

## All findings

### [Critical] Root account has no MFA

- **Tool:** prowler
- **Service:** iam · **Region:** us-east-1
- **Resource:** `root`
- **Status:** fail
- **Description:** The account root user does not have MFA enabled.
- **Remediation:** Enable a hardware or virtual MFA device on the root user.
- **Compliance:** CIS:1.5

### [Critical] S3 bucket allows public access

- **Tool:** prowler
- **Service:** s3 · **Region:** us-east-1
- **Resource:** `arn:aws:s3:::acme-prod-assets`
- **Status:** fail
- **Description:** Bucket 'acme-prod-assets' grants s3:GetObject to *.
- **Remediation:** Enable S3 Block Public Access at the account and bucket level.
- **Compliance:** CIS:2.1.5, NIST:SC-7

### [High] Hardcoded AWS access key in source

- **Tool:** ash
- **Service:** detect-secrets
- **Resource:** `app/config.py:42`
- **Status:** fail
- **Description:** Possible AWS secret in config.py.
- **Remediation:** Remove the secret, rotate the key, use environment variables or Secrets Manager.
- **Compliance:** CWE-798

### [High] Privilege escalation path: DeployRole

- **Tool:** cloudsplaining
- **Service:** iam
- **Resource:** `DeployRole`
- **Status:** fail
- **Description:** Policy 'DeployRole' grants iam:CreatePolicyVersion, iam:PassRole.
- **Remediation:** Apply least privilege; scope iam:PassRole with a condition.
- **Compliance:** CIS-1.16, IAM-least-privilege

### [High] Resource exposure: BackupRole

- **Tool:** cloudsplaining
- **Service:** iam
- **Resource:** `BackupRole`
- **Status:** fail
- **Description:** Policy 'BackupRole' grants s3:PutBucketPolicy on *.
- **Remediation:** Restrict permissions-management actions to specific resources.
- **Compliance:** IAM-least-privilege

### [High] Anonymous access bound to cluster role

- **Tool:** hardeneks
- **Service:** eks · **Region:** eu-central-1
- **Resource:** `prod-cluster/kube-system`
- **Status:** fail
- **Description:** system:anonymous is bound via a ClusterRoleBinding.
- **Remediation:** Remove the ClusterRoleBinding granting access to system:anonymous.
- **Compliance:** EKS-best-practices

### [High] Security group exposes SSH to 0.0.0.0/0

- **Tool:** prowler
- **Service:** ec2 · **Region:** eu-central-1
- **Resource:** `sg-0a1b2c3d`
- **Status:** fail
- **Description:** sg-0a1b2c3d allows inbound 22 from anywhere.
- **Remediation:** Restrict ingress to known CIDR ranges or use SSM Session Manager.
- **Compliance:** CIS:5.2

### [Medium] S3 bucket has no access logging

- **Tool:** ash
- **Service:** checkov
- **Resource:** `terraform/s3.tf:14`
- **Status:** fail
- **Description:** aws_s3_bucket.assets missing logging block.
- **Remediation:** Add a logging {} block referencing a log bucket.
- **Compliance:** CIS:2.6

### [Medium] Wildcards used in Role rules

- **Tool:** hardeneks
- **Service:** eks · **Region:** eu-central-1
- **Resource:** `prod-cluster/default`
- **Status:** fail
- **Description:** Role 'app-role' uses '*' for verbs.
- **Remediation:** Replace wildcard verbs with explicit verbs.
- **Compliance:** EKS-best-practices

### [Medium] CloudTrail not enabled in all regions

- **Tool:** prowler
- **Service:** cloudtrail · **Region:** us-east-1
- **Resource:** `account`
- **Status:** fail
- **Description:** Multi-region trail missing in 3 regions.
- **Remediation:** Create an organization multi-region CloudTrail.
- **Compliance:** CIS:3.1

### [Info] RDS instance is encrypted

- **Tool:** prowler
- **Service:** rds · **Region:** eu-central-1
- **Resource:** `arn:aws:rds:eu-central-1:123456789012:db:prod-db`
- **Status:** pass
- **Description:** prod-db has storage encryption enabled.
- **Compliance:** CIS:2.3.1


---
_Generated by [SentryHive](https://github.com/d2k-klin/sentryhive). No data leaves your machine._