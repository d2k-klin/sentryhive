# Scanners

SentryHive wraps six open-source tools behind one interface. Each is pinned in the
Docker image; provenance is recorded in the report.

| Scanner | Upstream | Target | Role | Access |
|---------|----------|--------|------|--------|
| Prowler | [prowler-cloud/prowler](https://github.com/prowler-cloud/prowler) | Account configuration and compliance | core | Read-only IAM |
| Cloudsplaining | [salesforce/cloudsplaining](https://github.com/salesforce/cloudsplaining) | IAM policy risk | core | Read-only IAM |
| CloudFox | [BishopFox/cloudfox](https://github.com/BishopFox/cloudfox) | AWS attack surface and privilege paths | core | Read-only IAM |
| HardenEKS | [aws-samples/hardeneks](https://github.com/aws-samples/hardeneks) | AWS EKS best practices | opt-in (`--kubernetes`) | IAM + in-cluster RBAC |
| Kubescape | [kubescape/kubescape](https://github.com/kubescape/kubescape) | Kubernetes posture and misconfiguration | opt-in (`--kubernetes`) | IAM + in-cluster RBAC |
| ASH | [awslabs/automated-security-helper](https://github.com/awslabs/automated-security-helper) | Local code/IaC | opt-in (`--scanners ...,ash`) | Local files |

## What each covers

### Prowler

Account-wide configuration and compliance. It maps evidence to CIS, PCI-DSS,
SOC 2, ISO 27001, HIPAA, and NIST 800-53. SentryHive consumes OCSF JSON.

### Cloudsplaining

IAM policies with privilege-escalation, resource exposure, data exfiltration, and
credential exposure. These results drive the IAM escalation section.

### CloudFox

SentryHive runs the focused `workloads`, `role-trusts`, `resource-trusts`,
`endpoints`, and `network-ports` modules. Modules that collect secrets, environment
variables, userdata, or loot are deliberately excluded.

CloudFox is an enumeration tool, not a compliance finding generator. SentryHive marks
administrator workloads, confirmed escalation paths, root trusts without an external
ID, and public resource policies as failures. Public endpoints and reachable services
stay informational until a human validates intent and controls.

### HardenEKS and Kubescape

HardenEKS supplies AWS-specific EKS checks; Kubescape adds broader Kubernetes
misconfiguration and posture controls. `--kubernetes` runs both after a shared
`kubectl auth can-i list pods -A` preflight. See [EKS access](eks-access.md).

### ASH

Static analysis of source and IaC on disk. It does not touch a live AWS account;
point it at a directory with `--source-dir`.

## Version pinning and provenance

Pins live in the [Dockerfile](../Dockerfile). The scope/tool-execution section records
the versions that produced the evidence. The weekly Tool Watch checks every upstream
release and must adapt wrappers/normalizers when a CLI or schema changes.

## Evaluated but not bundled by default

- **Cartography** offers valuable graph relationships but requires Neo4j and a
  persistent ingestion lifecycle. That is a separate deployment profile rather than
  a dependency of the portable one-image scanner.
- **zizmor and OSV-Scanner** are useful focused source scanners. SentryHive currently
  keeps ASH as its single local source-security entry point to avoid overlapping
  outputs and dependency bloat.
- **Falco and Tetragon** are runtime detection systems, not point-in-time assessment
  scanners, so they belong in a monitoring architecture.

## Missing scanners

When running from source, an unavailable binary is reported as `skipped` and the
combined report is marked incomplete so a missing tool cannot look like a clean
assessment. The Docker image includes all six tools.

## Adding a scanner

See [architecture.md](architecture.md#adding-a-scanner) and
[CONTRIBUTING.md](../CONTRIBUTING.md).
