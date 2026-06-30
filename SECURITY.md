# Security Policy

SentryHive is a security tool, so we hold ourselves to a high bar.

## Reporting a vulnerability

**Do not open a public issue for security vulnerabilities.**

Instead, use GitHub's [private vulnerability reporting](https://github.com/d2k-klin/sentryhive/security/advisories/new) (Security → Report a vulnerability). We aim to acknowledge reports within 72 hours and to ship a fix or mitigation as quickly as the severity warrants.

Please include:

- A description of the issue and its impact
- Steps to reproduce
- Affected version / commit
- Any suggested remediation

## Our security model

These are the properties SentryHive is designed to uphold. Reports that these are violated are treated as vulnerabilities:

- **No data exfiltration.** SentryHive does not transmit scan results anywhere. All findings stay on the machine that runs it; reports are written to local disk only.
- **Read-only by design.** The bundled scanners and the shipped IAM policy/role grant **only read-only** AWS permissions. SentryHive performs no write, modify, or delete actions against your account.
- **Least privilege.** Use [`iam/least-privilege-policy.json`](iam/least-privilege-policy.json) or [`iam/audit-role.cfn.yaml`](iam/audit-role.cfn.yaml) to grant the minimum access required. Prefer role assumption with an external ID for cross-account scans.
- **Credential hygiene.** Credentials are resolved, used in-process, and passed to child scanners via environment only for the duration of the run. They are never written to the report or to disk by SentryHive.

## Supply chain

SentryHive pulls in third-party scanners (Prowler, Cloudsplaining, hardeneks, ASH). Pin the image digest in production and review the [Dockerfile](Dockerfile) for the exact versions installed. Run the image you build yourself if you require provenance guarantees.

## Supported versions

This project is pre-1.0; security fixes are applied to `main`. Pin to a released tag or image digest for stability.
