"""Aggregate normalized findings across scanners: dedup, rank, summarize.

For the consultant/auditor audience the report is the product, so this layer also
computes the evidence-grade extras the report surfaces: per-framework compliance
posture and the IAM privilege-escalation highlights.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from sentryhive import __version__
from sentryhive.models import Finding, Severity
from sentryhive.scanners.base import ScanResult


@dataclass
class ScannerSummary:
    name: str
    status: str
    findings: int
    message: str = ""
    version: str = ""


@dataclass
class FrameworkPosture:
    framework: str
    passed: int
    failed: int

    @property
    def total(self) -> int:
        return self.passed + self.failed

    @property
    def pass_pct(self) -> int:
        return round(100 * self.passed / self.total) if self.total else 0


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
    compliance: list[FrameworkPosture] = field(default_factory=list)
    iam_highlights: list[Finding] = field(default_factory=list)
    # Consultant / evidence metadata.
    client_name: str = ""
    logo_data_uri: str = ""
    tool_version: str = __version__
    accounts: list[str] = field(default_factory=list)  # populated for roll-up reports
    is_rollup: bool = False

    @property
    def total(self) -> int:
        return len(self.findings)

    def to_dict(self) -> dict:
        return {
            "client_name": self.client_name,
            "account_id": self.account_id,
            "accounts": self.accounts,
            "identity_arn": self.identity_arn,
            "regions": self.regions,
            "generated_at": self.generated_at,
            "sentryhive_version": self.tool_version,
            "summary": {
                "total": self.total,
                "by_severity": self.severity_counts,
                "by_status": self.status_counts,
                "services": self.services,
                "compliance": [vars(c) | {"pass_pct": c.pass_pct, "total": c.total}
                               for c in self.compliance],
            },
            "scanners": [vars(s) for s in self.scanners],
            "findings": [f.to_dict() for f in self.findings],
        }


def dedup(findings: list[Finding]) -> list[Finding]:
    """Collapse the same resource+check reported by multiple tools.

    When two tools flag the same thing (e.g. an over-privileged role surfaced by
    both Prowler and Cloudsplaining), keep the highest-severity instance and record
    the contributing tools on the survivor's compliance refs. 'pass' never absorbs
    a 'fail'.
    """
    best: dict[str, Finding] = {}
    for f in findings:
        key = f.dedup_key
        existing = best.get(key)
        if existing is None:
            best[key] = f
            continue
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


def compliance_posture(findings: list[Finding]) -> list[FrameworkPosture]:
    """Per-framework pass/fail tallies, for the exec summary's compliance posture."""
    tally: dict[str, FrameworkPosture] = {}
    for f in findings:
        if f.status not in ("pass", "fail"):
            continue
        for fw in f.frameworks():
            p = tally.setdefault(fw, FrameworkPosture(framework=fw, passed=0, failed=0))
            if f.status == "pass":
                p.passed += 1
            else:
                p.failed += 1
    # Most failures first — that's what the auditor cares about.
    return sorted(tally.values(), key=lambda p: (-p.failed, p.framework))


def iam_highlights(findings: list[Finding], limit: int = 5) -> list[Finding]:
    """The privilege-escalation / IAM-takeover narrative for the exec summary."""
    priv = [
        f for f in findings
        if f.status == "fail"
        and (f.tool == "cloudsplaining" or f.service == "iam")
        and ("escalat" in (f.check + f.title).lower()
             or "exposure" in (f.check + f.title).lower()
             or f.tool == "cloudsplaining")
    ]
    return rank(priv)[:limit]


def _summaries(results: list[ScanResult]) -> tuple[list[Finding], list[ScannerSummary]]:
    all_findings: list[Finding] = []
    summaries: list[ScannerSummary] = []
    for r in results:
        summaries.append(
            ScannerSummary(name=r.scanner, status=r.status.value,
                           findings=len(r.findings), message=r.message, version=r.version)
        )
        all_findings.extend(r.findings)
    return all_findings, summaries


def _counts(findings: list[Finding]) -> tuple[dict[str, int], dict[str, int], list[str]]:
    severity_counts = {s.label: 0 for s in reversed(list(Severity))}
    status_counts: dict[str, int] = {"fail": 0, "pass": 0, "info": 0}
    services: set[str] = set()
    for f in findings:
        severity_counts[f.severity.label] += 1
        status_counts[f.status] = status_counts.get(f.status, 0) + 1
        if f.service:
            services.add(f.service)
    return severity_counts, status_counts, sorted(services)


def build_report(
    results: list[ScanResult],
    *,
    account_id: str,
    identity_arn: str,
    regions: list[str],
    generated_at: str,
    client_name: str = "",
    logo_data_uri: str = "",
    top_n: int = 10,
) -> Report:
    all_findings, summaries = _summaries(results)
    deduped = rank(dedup(all_findings))
    severity_counts, status_counts, services = _counts(deduped)
    fails = [f for f in deduped if f.status == "fail"]

    return Report(
        account_id=account_id,
        identity_arn=identity_arn,
        regions=regions,
        generated_at=generated_at,
        findings=deduped,
        severity_counts=severity_counts,
        status_counts=status_counts,
        services=services,
        scanners=summaries,
        top_risks=fails[:top_n],
        compliance=compliance_posture(deduped),
        iam_highlights=iam_highlights(deduped),
        client_name=client_name,
        logo_data_uri=logo_data_uri,
    )


def build_rollup(reports: list[Report], *, generated_at: str, client_name: str = "",
                 logo_data_uri: str = "", top_n: int = 10) -> Report:
    """Combine per-account reports into one roll-up across all scanned accounts.

    Findings keep their account_id so the consultant can trace each back; the roll-up
    is for the leadership-level cross-account view.
    """
    combined: list[Finding] = []
    scanner_status: dict[str, ScannerSummary] = {}
    accounts: list[str] = []
    regions: set[str] = set()
    for rep in reports:
        accounts.append(rep.account_id)
        regions.update(rep.regions)
        combined.extend(rep.findings)
        for s in rep.scanners:
            agg = scanner_status.get(s.name)
            if agg is None:
                scanner_status[s.name] = ScannerSummary(s.name, s.status, s.findings, s.message, s.version)
            else:
                agg.findings += s.findings

    ranked = rank(combined)  # no cross-account dedup: same ARN in two accounts is distinct
    severity_counts, status_counts, services = _counts(ranked)
    fails = [f for f in ranked if f.status == "fail"]

    return Report(
        account_id="multiple",
        identity_arn="",
        regions=sorted(regions),
        generated_at=generated_at,
        findings=ranked,
        severity_counts=severity_counts,
        status_counts=status_counts,
        services=services,
        scanners=list(scanner_status.values()),
        top_risks=fails[:top_n],
        compliance=compliance_posture(ranked),
        iam_highlights=iam_highlights(ranked),
        client_name=client_name,
        logo_data_uri=logo_data_uri,
        accounts=accounts,
        is_rollup=True,
    )
