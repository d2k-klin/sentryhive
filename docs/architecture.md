# Architecture

How SentryHive turns AWS credentials into one consolidated report. This is the
*explanation* doc — for contributors and the curious.

## Pipeline

```
AWS creds → CLI → auth (STS verify) ─┬─ Prowler ───────┐
            (per account)            ├─ Cloudsplaining ─┤ each → normalized Findings
                                     ├─ hardeneks (opt) ─┤
                                     └─ ASH (opt) ───────┘
                                              ↓
                                  Aggregator: dedup + rank + compliance posture
                                              ↓
                          Report generator → HTML · PDF · Markdown · JSON
                          (multi-account: per-account reports + roll-up)
```

## Modules

| Module | Responsibility |
|--------|----------------|
| [`cli.py`](../sentryhive/cli.py) | Typer CLI; orchestrates auth → scanners → aggregate → report. |
| [`auth.py`](../sentryhive/auth.py) | Credential resolution, STS identity verification, multi-account contexts, EKS discovery. |
| [`scanners/`](../sentryhive/scanners) | One wrapper per tool behind a common `Scanner` interface, plus a registry. |
| [`normalize.py`](../sentryhive/normalize.py) | Per-tool parsers → the unified `Finding` schema. |
| [`models.py`](../sentryhive/models.py) | `Finding`, `Severity`, compliance-framework parsing. |
| [`aggregate.py`](../sentryhive/aggregate.py) | Dedup, ranking, compliance posture, IAM highlights, roll-up. |
| [`report/`](../sentryhive/report) | Jinja2 templates + generator (HTML/MD/JSON/PDF). |

## Unified finding schema

The heart of the project: every scanner's output is normalized into one shape so the
aggregator and report layer never care which tool produced a finding.

```python
Finding(
    tool, check, title, description,
    severity,            # Severity enum (Info..Critical)
    resource, service, region,
    status,              # fail | pass | info
    remediation,
    compliance_refs,     # ["CIS:2.1.5", "PCI-DSS:1.3.1", ...]
    account_id,
    id,                  # stable fingerprint for dedup
)
```

Parsers are defensive: tool output schemas drift between versions, so fields are read
best-effort and unmappable data degrades to sensible defaults rather than raising.

## Scanner interface

```python
class Scanner:
    name: str
    binary: str           # CLI that must be on PATH
    requires_aws: bool    # live-account vs local-files

    def run(self, ctx, workdir) -> ScanResult: ...   # base: availability + version + error handling
    def _scan(self, ctx, workdir) -> ScanResult: ... # subclass implements
```

The base class handles "tool not installed" (→ `skipped`), version capture, and
exception isolation so **one scanner failing never aborts the run**.

## Aggregation

1. **Dedup** — findings sharing `service + resource + check` collapse to the
   highest-severity instance, tagged `flagged-by:tool-a+tool-b`. Cross-account
   findings are never merged (same ARN in two accounts is distinct).
2. **Rank** — most-severe first, failures before passes.
3. **Compliance posture** — pass/fail tallied per framework from `compliance_refs`.
4. **IAM highlights** — privilege-escalation/exposure findings surfaced for the exec summary.

## Multi-account & roll-up

`auth.build_contexts` yields one verified context per `--role-arn`. Each account
produces its own report; `aggregate.build_rollup` combines them into a cross-account
view (per-account reports under `reports/<account-id>/`, roll-up at `reports/`).

## Report generation

The branded HTML is the single source of truth. PDF reuses it via the template's
`@media print` rules (cover page, page numbers, scope page), rendered locally by
WeasyPrint (default) or Chromium. Markdown and JSON are separate templates/serializers.

## Adding a scanner

1. Add `parse_<tool>()` to `normalize.py` returning `list[Finding]`.
2. Add `scanners/<tool>.py` subclassing `Scanner`, implementing `_scan`.
3. Register it in `scanners/__init__.py`.
4. Add the tool to the [Dockerfile](../Dockerfile).
5. Add a parser test with a fixture.

Nothing in the aggregator, report layer, or CLI needs to change. See
[CONTRIBUTING.md](../CONTRIBUTING.md).
