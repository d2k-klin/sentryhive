# SentryHive documentation

SentryHive points at one or more AWS accounts and produces a consolidated,
evidence-grade security report from best-in-class open-source scanners.

These docs follow the [Diátaxis](https://diataxis.fr/) structure — tutorials,
how-to guides, reference, and explanation are kept separate.

## Start here (tutorials)

- [Getting started](getting-started.md) — your first scan in under 5 minutes.

## How-to guides (tasks)

- [Installation](installation.md) — Docker, from source, PyPI.
- [Usage](usage.md) — common tasks + the full flag reference.
- [Authentication](authentication.md) — profiles, static keys, assume-role, external ID.
- [IAM permissions](iam-permissions.md) — least-privilege policy + client onboarding.
- [EKS access](eks-access.md) — granting in-cluster access for EKS hardening.
- [CI/CD](ci-cd.md) — run SentryHive as a pipeline security gate.

## Reference (lookup)

- [Scanners](scanners.md) — what each bundled tool does + version pinning.
- [Reports](reports.md) — formats, branding, and how to interpret findings.
- [Configuration](configuration.md) — environment variables.

## Explanation (understanding)

- [Architecture](architecture.md) — how orchestration, normalization, and reporting fit together.

## Help

- [FAQ](faq.md)
- [Troubleshooting](troubleshooting.md)

## Trust

SentryHive only ever performs **read-only** AWS calls, and **no scan data leaves
your machine** — scanning and PDF generation are fully local. See
[IAM permissions](iam-permissions.md) and [SECURITY.md](../SECURITY.md).

> Only scan accounts you are authorized to scan.
