# Changelog

All notable changes to SentryHive are documented here.
The format is based on [Keep a Changelog](https://keepachangelog.com/), and this
project adheres to [Semantic Versioning](https://semver.org/).

The **Security** group flags any change affecting permissions, credential handling,
or scanner behavior. Bundled-scanner version bumps are noted explicitly because they
change findings output.

## [Unreleased]

## [1.1.1] - 2026-08-17

### Fixed

- The Backup & recovery section no longer gathers confidentiality checks that merely
  mention a recovery term. `documentdb_cluster_public_snapshot` (exposure) and
  `..._replication_group_auth_enabled` (authentication) matched on "snapshot" and
  "replication"; on a live account they were 34 of 117 gathered findings, nearly all
  passes, making the section read healthier than the account actually was.

### Security

- Restore-testing and backup-freshness evidence is now reported as **unknown** when
  backup plans cannot be read, instead of being omitted. Previously an unreadable plan
  list was treated identically to "no plan exists", so the restore-testing control —
  the one an auditor is most likely to ask about — disappeared from the report entirely
  rather than being flagged as unverified.

## [1.1.0] - 2026-08-17

### Added

- **Backup & recovery assessment.** A new native `resilience` scanner, run by default
  alongside Prowler, Cloudsplaining and CloudFox. It is the first scanner with no
  upstream binary: it calls the AWS Backup and RDS read APIs directly, so it needs
  nothing installed and is never skipped for a missing tool.
- Nine recovery checks: backup plan coverage, vault lock (immutability), off-site copy
  actions, retention against `--retention-days`, schedule cadence and backup freshness
  against `--rpo-hours`, failed backup jobs, restore-test evidence, and RDS backup
  retention. Evidence maps to SOC 2 (A1.2/A1.3), ISO 27001 (A.8.13/A.5.30),
  NIST 800-53 (CP-9/CP-10) and HIPAA §164.308(a)(7).
- `--rpo-hours` (default 24) and `--retention-days` (default 35) so retention and
  cadence are judged against the engagement's stated objectives rather than a
  hardcoded assumption.
- A **Backup & recovery** section in the HTML and Markdown reports. It gathers
  recovery evidence from every scanner, so the backup-related findings the wrapped
  tools already produced — RDS automated backups, S3 versioning, DynamoDB PITR, EFS
  backup — are now presented as one control area instead of scattered through the
  register.

### Security

- New read-only IAM actions for the resilience scanner (`backup:ListBackupPlans`,
  `GetBackupPlan`, `ListBackupVaults`, `DescribeBackupVault`, `ListBackupJobs`,
  `ListRestoreJobs`, `ListRestoreTestingPlans`, `rds:DescribeDBInstances`), added to
  the shipped policy, CloudFormation template and Terraform module. No write, modify
  or delete actions are requested.
- A recovery control that cannot be read is reported as **informational**
  ("Could not verify …"), never as passing. Informational findings are excluded from
  the compliance posture, so a missing permission can never be mistaken for a
  satisfied control.

## [0.0.5] - 2026-08-14

### Changed

- Upgraded Prowler to 5.37.0, Cloudsplaining to 0.9.1, ASH to 3.5.9,
  Kubescape to 4.0.12, and AWS CLI to 2.36.23.
- Isolated Cloudsplaining and ASH from Prowler's incompatible dependency pins.
- Held Prowler below 5.38.0 because that release's cryptography requirements are
  internally inconsistent with its pinned Alibaba Cloud SDK.
- Updated direct Python dependencies and the pinned CodeQL and Docker login actions.

### Security

- Kept the Prowler cryptography audit exception scoped to its isolated environment;
  ASH now installs the patched cryptography 50 release independently.
- Documented the five temporary audit exceptions forced by Prowler 5.37.0's exact
  cryptography and h2 pins; Cloudsplaining and ASH audit cleanly.
- Updated and verified the SHA-256 pins for both Kubescape Linux architectures.

## [0.0.4] - 2026-07-27

### Fixed
- Scanner integrity verification now accepts CloudFox's actual `cloudfox version X.Y.Z`
  output format instead of requiring a `v` prefix.
- The runtime `sentryhive --version` value now stays aligned with the package version.

## [0.0.3] - 2026-07-24

### Added
- **CloudFox 2.0.5** as a core AWS attack-surface scanner, using focused modules
  that avoid secret/loot collection and distinguish confirmed risks from observations.
- **Kubescape 4.0.11** alongside HardenEKS for deeper, opt-in Kubernetes posture.
- Explicit `--kubernetes / --no-kubernetes` scope choice; `--eks` remains a
  compatibility alias.

### Changed
- One scan now emits one engagement-wide report set, including multi-account,
  Kubernetes, and optional ASH evidence.
- HTML/Markdown/PDF reports are fail-first. Severity summaries exclude pass evidence;
  HTML keeps the full filterable register and PDF uses a bounded failure register.
- Report covers and footers identify OSS SentryHive and its creator, Mr. D.
- Authentication and onboarding docs now distinguish credentials, cross-account
  roles, AWS permissions, and Kubernetes RBAC.

### Security
- HTML autoescaping now applies to `.html.j2` report templates, preventing
  scanner-controlled text from becoming executable markup.
- CloudFox and Kubescape release binaries are SHA-256 verified in the Docker build.
- Audit-role templates include the additional read-only CloudFox permissions.

## [0.0.2] - 2026-07-01

### Changed
- Scanner execution errors no longer prevent report generation; the resulting report
  is marked incomplete and the command exits non-zero.
- Report templates and golden fixtures now surface scanner execution status.

## [0.0.1] - 2026-06-30

Initial release — a working v1 for security consultants and auditors.

### Added
- Single-command orchestration of open-source AWS scanners with a unified finding schema.
- Core scanners: **Prowler** (config & compliance) and **Cloudsplaining** (IAM policy risk).
- **EKS hardening** via hardeneks as an opt-in second phase (`--eks`), with per-cluster
  preflight access checks and graceful per-cluster skips.
- **ASH** (local IaC/code) as an opt-in scanner (`--scanners ...,ash`).
- Authentication via assume-role (primary, `--external-id` supported), profile, or static keys.
- **Multi-account scanning** in one run via repeated `--role-arn`, with per-account
  reports plus a cross-account roll-up.
- Evidence-grade reports: branded HTML (`--client-name`, `--logo`), Markdown, JSON, and
  **PDF** (`--pdf`) rendered locally via WeasyPrint (optional Chromium engine).
- Per-framework **compliance posture** (CIS, PCI-DSS, SOC 2, NIST 800-53, …) and an
  **IAM privilege-escalation highlights** section in the exec summary.
- Cross-tool dedup, severity ranking, and a "top risks" list.
- Least-privilege IAM templates (CloudFormation + Terraform) and EKS access onboarding
  artifacts.
- GitHub Actions reusable scan workflow with PR-comment mode and a `--fail-on` CI gate.

### Security
- All scanner access is read-only; shipped IAM grants only read permissions.
- Scanning and PDF generation run fully locally — no scan data leaves the operator's machine.
- External ID is supported for cross-account role assumption.

[Unreleased]: https://github.com/d2k-klin/sentryhive/compare/v1.1.1...HEAD
[1.1.1]: https://github.com/d2k-klin/sentryhive/releases/tag/v1.1.1
[1.1.0]: https://github.com/d2k-klin/sentryhive/releases/tag/v1.1.0
[0.0.5]: https://github.com/d2k-klin/sentryhive/releases/tag/v0.0.5
[0.0.4]: https://github.com/d2k-klin/sentryhive/releases/tag/v0.0.4
[0.0.3]: https://github.com/d2k-klin/sentryhive/releases/tag/v0.0.3
[0.0.2]: https://github.com/d2k-klin/sentryhive/releases/tag/v0.0.2
[0.0.1]: https://github.com/d2k-klin/sentryhive/releases/tag/v0.0.1
