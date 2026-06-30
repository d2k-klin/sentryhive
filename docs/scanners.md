# Scanners

SentryHive wraps four open-source tools behind one interface. Each is pinned in the
Docker image; provenance is transparent so you can defend findings.

| Scanner | Upstream | Target | Role | Access |
|---------|----------|--------|------|--------|
| Prowler | [prowler-cloud/prowler](https://github.com/prowler-cloud/prowler) | Live account config & compliance (500+ checks) | core | Read-only IAM |
| Cloudsplaining | [salesforce/cloudsplaining](https://github.com/salesforce/cloudsplaining) | IAM policy risk (priv-esc, over-permission, exposure) | core | Read-only IAM |
| hardeneks | [aws-samples/hardeneks](https://github.com/aws-samples/hardeneks) | EKS best practices | opt-in (`--eks`) | IAM **+ in-cluster RBAC** |
| ASH | [awslabs/automated-security-helper](https://github.com/awslabs/automated-security-helper) | Local IaC/code (Terraform, CFN, secrets) | opt-in (`--scanners ...,ash`) | Local files only |

## What each covers

### Prowler (core)
Account-wide configuration and compliance. Maps findings to CIS, PCI-DSS, SOC 2,
ISO 27001, HIPAA, and NIST 800-53 — the backbone of the compliance posture in the
report. Output is consumed as OCSF/JSON.

### Cloudsplaining (core)
Analyzes IAM policies for privilege-escalation paths, resource exposure, data
exfiltration, and credential exposure. Drives the IAM highlights section — the
account-takeover narrative.

### hardeneks (opt-in, `--eks`)
EKS best-practice checks that read *inside* the cluster. Because it needs in-cluster
RBAC (not just IAM), it is a separate opt-in phase with a per-cluster preflight access
check. See [EKS access](eks-access.md).

### ASH (opt-in)
Static analysis of code/IaC on disk — Terraform, CloudFormation, secrets, etc. Unlike
the others it does not touch a live account; point it at a directory with
`--source-dir`.

## Version pinning & provenance

The bundled versions are pinned in the [Dockerfile](../Dockerfile). Each report's
scope/scanners section records the exact version that produced the findings (evidence
integrity). Pin the image digest in production if you need reproducibility guarantees.

A scanner version bump can change findings output; such bumps are called out
explicitly in the [CHANGELOG](../CHANGELOG.md).

## Missing scanners

Running from source without a tool installed isn't fatal: SentryHive reports that
scanner as `skipped` with an actionable message and continues. The Docker image
includes all of them.

## Adding a scanner

The architecture makes a fifth scanner a small change — see
[architecture.md](architecture.md#adding-a-scanner) and [CONTRIBUTING.md](../CONTRIBUTING.md).
