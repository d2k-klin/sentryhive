# Changelog

All notable changes to SentryHive are documented here.
The format is based on [Keep a Changelog](https://keepachangelog.com/), and this
project adheres to [Semantic Versioning](https://semver.org/).

The **Security** group flags any change affecting permissions, credential handling,
or scanner behavior. Bundled-scanner version bumps are noted explicitly because they
change findings output.

## [Unreleased]

## [0.1.0] - 2026-06-30

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

[Unreleased]: https://github.com/d2k-klin/sentryhive/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/d2k-klin/sentryhive/releases/tag/v0.1.0
