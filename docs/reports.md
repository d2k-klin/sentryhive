# Reports

SentryHive writes up to four artifacts per scan. For consultants, the **report is the
deliverable** — so it's branded, dated, and evidence-grade.

## Formats

| File | Format | Use |
|------|--------|-----|
| `report.html` | Self-contained HTML | Interactive review (filter by severity/tool/status/text). |
| `report.pdf` | PDF | The client deliverable — branded, paginated, with cover + scope pages. |
| `report.md` | Markdown | PR comments, CI artifacts, internal notes. |
| `findings.json` | JSON | Machine-readable; pipe into other systems. |

Select with `--format` (comma list) or add PDF with `--pdf`:

```bash
sentryhive scan ... --format html,pdf,json
sentryhive scan ... --pdf            # adds pdf to the default html,md,json
```

Default formats are `html,md,json`; PDF is opt-in to keep default runs fast.

## Output layout

- **Single account:** files land directly in `reports/`.
- **Multiple accounts:** `reports/<account-id>/` per account, plus a cross-account
  roll-up in `reports/`.
- **ASH (local IaC):** `reports/local-iac/` when combined with an account scan, else
  `reports/`.

## Branding

```bash
sentryhive scan ... --client-name "Acme Corp" --logo ./acme-logo.png --pdf
```

`--client-name` appears in the header and PDF cover; `--logo` is embedded inline
(base64) so the HTML/PDF stays a single portable file.

## PDF

PDF reuses the HTML as the single source of truth, rendered locally:

- **WeasyPrint** (default) — pure-Python, no browser, no network. Recommended.
- **Chromium** (`--pdf-engine chromium`) — pixel-perfect, runs JS; needs a Chromium/
  Chrome binary on PATH.

The PDF adds a **cover page** (client, logo, "Confidential", scan date, version), a
**scope & methodology page** (accounts, identity, scanners + versions — evidence
integrity), a **table of contents**, repeating **page numbers/footer**, and a static
severity listing (the interactive filters become plain content).

PDF generation is fully local — no cloud rendering, no external asset fetches (fonts
are bundled in the Docker image). The "no data leaves your machine" guarantee extends
to PDF.

If WeasyPrint isn't installed, SentryHive skips the PDF with a warning and still
writes the other formats.

## Interpreting findings

### Severity

`Critical > High > Medium > Low > Info`. Severities from each tool are normalized into
this scale. Findings are ranked most-severe first, failures before passes.

### Status

- `fail` — the check did not pass; this is a finding to act on.
- `pass` — the check passed (kept for compliance posture math).
- `info` — informational.

### Compliance mapping

Findings carry `compliance_refs` like `CIS:2.1.5` or `PCI-DSS:1.3.1`. The exec summary
rolls these into a **per-framework posture** (pass/fail and % pass). A finding tagged
"fails CIS 1.4" is auditor-defensible evidence, not a generic alert.

### IAM privilege-escalation highlights

The exec summary surfaces Cloudsplaining's privilege-escalation and resource-exposure
findings separately — the "here's how an attacker takes over the account" narrative.
Each names the policy/role and the dangerous actions it grants.

### Dedup

When two tools flag the same `service + resource + check`, SentryHive keeps the
highest-severity instance and tags it `flagged-by:tool-a+tool-b` so you know it was
corroborated.

### The unified schema

Every finding, regardless of source tool, has the same shape — see
[architecture.md](architecture.md#unified-finding-schema) and
[`examples/sample-findings.json`](../examples/sample-findings.json).
