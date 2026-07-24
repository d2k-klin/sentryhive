# 🛡️ SentryHive Security Report
**Client:** Acme Corp

## Scan metadata (evidence)

| | |
|---|---|
| **Account** | `123456789012` |
| **Identity** | `arn:aws:iam::123456789012:role/SentryHiveAudit` |
| **Regions** | us-east-1, eu-central-1 |
| **Generated** | 2026-07-24 00:00:00 UTC |
| **SentryHive** | v0.0.2 |
| **Scanners** | prowler (Prowler 5.36.0), cloudsplaining (cloudsplaining 0.8.2), cloudfox (cloudfox version 2.0.5), hardeneks (hardeneks 1.1.1), kubescape (v4.0.11) |
| **Evidence records** | 11 |
| **Failing findings** | 8 |

## Executive summary

### Failing findings by severity

| Severity | Count |
|----------|-------|
| Critical | 2 |
| High | 5 |
| Medium | 1 |
| Low | 0 |
| Info | 0 |

**Status:** 8 fail · 2 pass · 1 info
**Services covered:** apigateway, cloudtrail, ec2, eks, iam, kubernetes, rds, s3

### Compliance posture

| Framework | Pass | Fail | % pass |
|-----------|------|------|--------|
| CIS | 2 | 6 | 25% |
| PCI-DSS | 1 | 2 | 33% |
| NIST 800-53 | 0 | 1 | 0% |
| SOC 2 | 1 | 1 | 50% |

### IAM privilege-escalation highlights

- **[High]** `DeployRole` — Privilege escalation path: DeployRole
- **[High]** `BackupRole` — Resource exposure: BackupRole

### Top 8 risks

| # | Severity | Tool | Resource | Check | Compliance |
|---|----------|------|----------|-------|------------|
| 1 | Critical | prowler | `root` | Root account has no MFA | CIS:1.5, SOC2:CC6.1 |
| 2 | Critical | prowler | `arn:aws:s3:::acme-prod-assets` | S3 bucket allows public access | CIS:2.1.5, PCI-DSS:1.3.1, NIST:SC-7 |
| 3 | High | cloudsplaining | `DeployRole` | Privilege escalation path: DeployRole | CIS-1.16, IAM-least-privilege |
| 4 | High | cloudsplaining | `BackupRole` | Resource exposure: BackupRole | IAM-least-privilege |
| 5 | High | hardeneks | `prod-cluster/kube-system` | Anonymous access bound to cluster role | EKS-best-practices |
| 6 | High | kubescape | `prod-eks/2 affected resources` | Workloads should run as non-root | CIS:5.2.6 |
| 7 | High | prowler | `sg-0a1b2c3d` | Security group exposes SSH to 0.0.0.0/0 | CIS:5.2, PCI-DSS:1.2.1 |
| 8 | Medium | prowler | `org-trail` | CloudTrail log file validation disabled | CIS:3.2 |

## Scanners

| Scanner | Status | Findings | Version | Notes |
|---------|--------|----------|---------|-------|
| prowler | ok | 6 | Prowler 5.36.0 |  |
| cloudsplaining | ok | 2 | cloudsplaining 0.8.2 |  |
| cloudfox | ok | 1 | cloudfox version 2.0.5 |  |
| hardeneks | ok | 1 | hardeneks 1.1.1 |  |
| kubescape | ok | 1 | v4.0.11 |  |

## Kubernetes posture

Combined in-cluster HardenEKS and Kubescape checks, grouped by cluster.

| Severity | Cluster / resource | Region | Finding |
|----------|--------------------|--------|---------|
| High | `prod-cluster/kube-system` | eu-central-1 | Anonymous access bound to cluster role |
| High | `prod-eks/2 affected resources` | us-east-1 | Workloads should run as non-root |

## Failing findings

The complete pass evidence and informational observations are retained in the
companion `report.html` and `findings.json` artifacts.

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

### [High] Workloads should run as non-root

- **Source tool:** kubescape
- **Service:** kubernetes · **Region:** us-east-1
- **Resource:** `prod-eks/2 affected resources`
- **Status:** fail
- **Compliance control:** CIS:5.2.6
- **Description:** Kubescape found two affected workload resources in the selected cluster.
- **Remediation:** Set runAsNonRoot and a non-zero runAsUser in the pod security context.

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


---
_This report was generated by [OSS SentryHive](https://github.com/d2k-klin/sentryhive) by Mr. D · v0.0.2. No data leaves your machine._
