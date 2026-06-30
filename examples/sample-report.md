# 🛡️ SentryHive Security Report
**Client:** Acme Corp

## Scan metadata (evidence)

| | |
|---|---|
| **Account** | `123456789012` |
| **Identity** | `arn:aws:iam::123456789012:role/SentryHiveAudit` |
| **Regions** | us-east-1, eu-central-1 |
| **Generated** | 2026-06-30 12:00:00 UTC |
| **SentryHive** | v0.1.0 |
| **Scanners** | prowler (Prowler 4.5.0), cloudsplaining (cloudsplaining 0.7.0), hardeneks (hardeneks 0.12.0) |
| **Total findings** | 9 |

## Executive summary

### By severity

| Severity | Count |
|----------|-------|
| Critical | 2 |
| High | 4 |
| Medium | 1 |
| Low | 0 |
| Info | 2 |

**Status:** 7 fail · 2 pass · 0 info
**Services covered:** cloudtrail, ec2, eks, iam, rds, s3

### Compliance posture

| Framework | Pass | Fail | % pass |
|-----------|------|------|--------|
| CIS | 2 | 5 | 29% |
| PCI-DSS | 1 | 2 | 33% |
| NIST 800-53 | 0 | 1 | 0% |
| SOC 2 | 1 | 1 | 50% |

### IAM privilege-escalation highlights

- **[High]** `DeployRole` — Privilege escalation path: DeployRole
- **[High]** `BackupRole` — Resource exposure: BackupRole

### Top 7 risks

| # | Severity | Tool | Resource | Check | Compliance |
|---|----------|------|----------|-------|------------|
| 1 | Critical | prowler | `root` | Root account has no MFA | CIS:1.5, SOC2:CC6.1 |
| 2 | Critical | prowler | `arn:aws:s3:::acme-prod-assets` | S3 bucket allows public access | CIS:2.1.5, PCI-DSS:1.3.1, NIST:SC-7 |
| 3 | High | cloudsplaining | `DeployRole` | Privilege escalation path: DeployRole | CIS-1.16, IAM-least-privilege |
| 4 | High | cloudsplaining | `BackupRole` | Resource exposure: BackupRole | IAM-least-privilege |
| 5 | High | hardeneks | `prod-cluster/kube-system` | Anonymous access bound to cluster role | EKS-best-practices |
| 6 | High | prowler | `sg-0a1b2c3d` | Security group exposes SSH to 0.0.0.0/0 | CIS:5.2, PCI-DSS:1.2.1 |
| 7 | Medium | prowler | `org-trail` | CloudTrail log file validation disabled | CIS:3.2 |

## Scanners

| Scanner | Status | Findings | Version | Notes |
|---------|--------|----------|---------|-------|
| prowler | ok | 6 | Prowler 4.5.0 |  |
| cloudsplaining | ok | 2 | cloudsplaining 0.7.0 |  |
| hardeneks | ok | 1 | hardeneks 0.12.0 |  |

## EKS Hardening

In-cluster best-practice checks (hardeneks), grouped by cluster.

| Severity | Cluster / resource | Region | Finding |
|----------|--------------------|--------|---------|
| High | `prod-cluster/kube-system` | eu-central-1 | Anonymous access bound to cluster role |

## All findings

### [Critical] Root account has no MFA

- **Source tool:** prowler
- **Service:** iam · **Region:** us-east-1
- **Resource:** `root`
- **Status:** fail
- **Compliance control:** CIS:1.5, SOC2:CC6.1
- **Description:** The account root user does not have MFA enabled.
- **Remediation:** Enable a hardware or virtual MFA device on the root user.

### [Critical] S3 bucket allows public access

- **Source tool:** prowler
- **Service:** s3 · **Region:** us-east-1
- **Resource:** `arn:aws:s3:::acme-prod-assets`
- **Status:** fail
- **Compliance control:** CIS:2.1.5, PCI-DSS:1.3.1, NIST:SC-7
- **Description:** Bucket 'acme-prod-assets' grants s3:GetObject to *.
- **Remediation:** Enable S3 Block Public Access at the account and bucket level.

### [High] Privilege escalation path: DeployRole

- **Source tool:** cloudsplaining
- **Service:** iam
- **Resource:** `DeployRole`
- **Status:** fail
- **Compliance control:** CIS-1.16, IAM-least-privilege
- **Description:** Policy 'DeployRole' grants iam:CreatePolicyVersion, iam:PassRole.
- **Remediation:** Apply least privilege; scope iam:PassRole with a condition.

### [High] Resource exposure: BackupRole

- **Source tool:** cloudsplaining
- **Service:** iam
- **Resource:** `BackupRole`
- **Status:** fail
- **Compliance control:** IAM-least-privilege
- **Description:** Policy 'BackupRole' grants s3:PutBucketPolicy on *.
- **Remediation:** Restrict permissions-management actions to specific resources.

### [High] Anonymous access bound to cluster role

- **Source tool:** hardeneks
- **Service:** eks · **Region:** eu-central-1
- **Resource:** `prod-cluster/kube-system`
- **Status:** fail
- **Compliance control:** EKS-best-practices
- **Description:** system:anonymous is bound via a ClusterRoleBinding.
- **Remediation:** Remove the ClusterRoleBinding granting access to system:anonymous.

### [High] Security group exposes SSH to 0.0.0.0/0

- **Source tool:** prowler
- **Service:** ec2 · **Region:** eu-central-1
- **Resource:** `sg-0a1b2c3d`
- **Status:** fail
- **Compliance control:** CIS:5.2, PCI-DSS:1.2.1
- **Description:** sg-0a1b2c3d allows inbound 22 from anywhere.
- **Remediation:** Restrict ingress to known CIDR ranges or use SSM Session Manager.

### [Medium] CloudTrail log file validation disabled

- **Source tool:** prowler
- **Service:** cloudtrail · **Region:** us-east-1
- **Resource:** `org-trail`
- **Status:** fail
- **Compliance control:** CIS:3.2
- **Description:** Trail lacks log file integrity validation.
- **Remediation:** Enable log file validation on the trail.

### [Info] CloudTrail enabled in all regions

- **Source tool:** prowler
- **Service:** cloudtrail · **Region:** us-east-1
- **Resource:** `org-trail`
- **Status:** pass
- **Compliance control:** CIS:3.1, SOC2:CC7.2
- **Description:** Org multi-region trail present.

### [Info] RDS instance is encrypted

- **Source tool:** prowler
- **Service:** rds · **Region:** eu-central-1
- **Resource:** `arn:aws:rds:eu-central-1:123456789012:db:prod-db`
- **Status:** pass
- **Compliance control:** CIS:2.3.1, PCI-DSS:3.4
- **Description:** prod-db has storage encryption enabled.


---
_Generated by [SentryHive](https://github.com/d2k-klin/sentryhive) v0.1.0. No data leaves your machine._