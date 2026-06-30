"""Aggregate normalized findings across scanners: dedup, rank, summarize."""

from __future__ import annotations

from dataclasses import dataclass, field

from sentryhive.models import Finding, Severity
from sentryhive.scanners.base import ScanResult


@dataclass
class ScannerSummary:
    name: str
    status: str
    findings: int
    message: str = ""


@dataclass
class Report:
    """Everything the report layer needs, already aggregated and sorted."""

    account_id: str
    identity_arn: str
    regions: list[str]
    generated_at: str
    findings: list[Finding]
    severity_counts: dict[str, int]
    status_counts: dict[str, int]
    services: list[str]
    scanners: list[ScannerSummary]
    top_risks: list[Finding] = field(default_factory=list)

    @property
    def total(self) -> int:
        return len(self.findings)

    def to_dict(self) -> dict:
        return {
            "account_id": self.account_id,
            "identity_arn": self.identity_arn,
            "regions": self.regions,
            "generated_at": self.generated_at,
            "summary": {
                "total": self.total,
                "by_severity": self.severity_counts,
                "by_status": self.status_counts,
                "services": self.services,
            },
            "scanners": [vars(s) for s in self.scanners],
            "findings": [f.to_dict() for f in self.findings],
        }


def dedup(findings: list[Finding]) -> list[Finding]:
    """Collapse the same resource+check reported by multiple tools.

    When two tools flag the same thing (e.g. an over-privileged role surfaced by
    both Prowler and Cloudsplaining), keep the highest-severity instance and record
    the contributing tools on the survivor's check field via its compliance refs.
    'pass' findings never absorb a 'fail'.
    """
    best: dict[str, Finding] = {}
    for f in findings:
        key = f.dedup_key
        existing = best.get(key)
        if existing is None:
            best[key] = f
            continue
        # Prefer fails over passes, then higher severity.
        incoming_score = (f.status == "fail", int(f.severity))
        existing_score = (existing.status == "fail", int(existing.severity))
        if incoming_score > existing_score:
            merged_tools = sorted({existing.tool, f.tool})
            f.compliance_refs = sorted(set(f.compliance_refs) | set(existing.compliance_refs))
            if len(merged_tools) > 1:
                f.compliance_refs.append("flagged-by:" + "+".join(merged_tools))
            best[key] = f
        else:
            merged_tools = sorted({existing.tool, f.tool})
            existing.compliance_refs = sorted(set(existing.compliance_refs) | set(f.compliance_refs))
            if len(merged_tools) > 1 and not any(r.startswith("flagged-by:") for r in existing.compliance_refs):
                existing.compliance_refs.append("flagged-by:" + "+".join(merged_tools))
    return list(best.values())


def rank(findings: list[Finding]) -> list[Finding]:
    """Sort most-severe first, then failures before passes, then by tool/check."""
    return sorted(
        findings,
        key=lambda f: (-int(f.severity), f.status != "fail", f.tool, f.check),
    )


def build_report(
    results: list[ScanResult],
    *,
    account_id: str,
    identity_arn: str,
    regions: list[str],
    generated_at: str,
    top_n: int = 10,
) -> Report:
    all_findings: list[Finding] = []
    summaries: list[ScannerSummary] = []
    for r in results:
        summaries.append(
            ScannerSummary(name=r.scanner, status=r.status.value,
                           findings=len(r.findings), message=r.message)
        )
        all_findings.extend(r.findings)

    deduped = rank(dedup(all_findings))

    severity_counts = {s.label: 0 for s in reversed(list(Severity))}
    status_counts: dict[str, int] = {"fail": 0, "pass": 0, "info": 0}
    services: set[str] = set()
    for f in deduped:
        severity_counts[f.severity.label] += 1
        status_counts[f.status] = status_counts.get(f.status, 0) + 1
        if f.service:
            services.add(f.service)

    fails = [f for f in deduped if f.status == "fail"]
    top_risks = fails[:top_n]

    return Report(
        account_id=account_id,
        identity_arn=identity_arn,
        regions=regions,
        generated_at=generated_at,
        findings=deduped,
        severity_counts=severity_counts,
        status_counts=status_counts,
        services=sorted(services),
        scanners=summaries,
        top_risks=top_risks,
    )
