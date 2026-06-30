# FAQ

**Does SentryHive send my data anywhere?**
No. All scanning and report generation (including PDF) run locally. Findings are
written to local disk only. See [SECURITY.md](../SECURITY.md).

**Does it make any changes to my AWS account?**
No. Every action is read-only. The shipped IAM policy grants no write/modify/delete
permissions. See [IAM permissions](iam-permissions.md).

**What permissions does it need?**
The AWS-managed `SecurityAudit` + `ViewOnlyAccess` plus a few extra read-only actions.
Deploy the [client onboarding role](iam-permissions.md) for a least-privilege setup.

**Do I have to install Prowler, Cloudsplaining, etc.?**
Not with Docker — the image bundles everything. From source, install the tools you
want; missing ones are reported as `skipped`, not errors.

**Why didn't EKS hardening run?**
It's opt-in. The default run only detects and notes EKS clusters. Run with `--eks`,
and grant in-cluster access first — see [EKS access](eks-access.md).

**Can I scan several client accounts at once?**
Yes — repeat `--role-arn`. You get a per-account report plus a roll-up. See
[usage](usage.md#scan-multiple-accounts).

**How do I get a branded PDF for a client?**
`sentryhive scan ... --client-name "Acme Corp" --logo logo.png --pdf`. See
[Reports](reports.md#pdf).

**The PDF didn't generate — why?**
WeasyPrint (or its system libraries) isn't installed. Use the Docker image, or
`pip install "sentryhive[pdf]"` plus the pango/cairo system libs. SentryHive still
writes the other formats. See [Troubleshooting](troubleshooting.md).

**Which compliance frameworks are covered?**
Whatever Prowler maps (CIS, PCI-DSS, SOC 2, ISO 27001, HIPAA, NIST 800-53). The exec
summary shows per-framework posture. See [Reports](reports.md#compliance-mapping).

**Can I use it in CI?**
Yes — there's a reusable GitHub Actions workflow and a `--fail-on` gate. See
[CI/CD](ci-cd.md).

**Does it work on Windows?**
Via WSL2 or Docker. The scanners and WeasyPrint aren't supported on native Windows.

**How do I add another scanner?**
See [architecture.md](architecture.md#adding-a-scanner) and
[CONTRIBUTING.md](../CONTRIBUTING.md).
