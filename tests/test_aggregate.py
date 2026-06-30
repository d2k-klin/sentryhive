from sentryhive.aggregate import build_report, dedup, rank
from sentryhive.models import Finding, Severity
from sentryhive.scanners.base import ScanResult, ScanStatus


def _f(tool, sev, status="fail", service="iam", resource="role/x", check="overpriv"):
    return Finding(
        tool=tool,
        check=check,
        title=f"{tool} finding",
        description="d",
        severity=sev,
        service=service,
        resource=resource,
        status=status,
    )


def test_dedup_collapses_same_resource_check_keeps_highest():
    findings = [
        _f("prowler", Severity.MEDIUM),
        _f("cloudsplaining", Severity.HIGH),
    ]
    out = dedup(findings)
    assert len(out) == 1
    assert out[0].severity is Severity.HIGH
    assert any(r.startswith("flagged-by:") for r in out[0].compliance_refs)


def test_dedup_prefers_fail_over_pass():
    findings = [
        _f("prowler", Severity.CRITICAL, status="pass"),
        _f("prowler", Severity.LOW, status="fail"),
    ]
    out = dedup(findings)
    assert len(out) == 1
    assert out[0].status == "fail"


def test_rank_orders_by_severity_then_status():
    findings = [
        _f("a", Severity.LOW, resource="r1"),
        _f("b", Severity.CRITICAL, resource="r2"),
        _f("c", Severity.HIGH, status="pass", resource="r3"),
        _f("d", Severity.HIGH, resource="r4"),
    ]
    out = rank(findings)
    assert [f.severity for f in out][0] is Severity.CRITICAL
    # Among the two HIGH, the failing one comes before the passing one.
    highs = [f for f in out if f.severity is Severity.HIGH]
    assert highs[0].status == "fail"


def test_build_report_summary_counts_and_top_risks():
    results = [
        ScanResult(
            "prowler",
            ScanStatus.OK,
            findings=[
                _f("prowler", Severity.CRITICAL, resource="r1"),
                _f("prowler", Severity.LOW, resource="r2", status="pass"),
            ],
        ),
        ScanResult("ash", ScanStatus.SKIPPED, message="not installed"),
    ]
    report = build_report(
        results,
        account_id="123",
        identity_arn="arn:aws:iam::123:user/me",
        regions=["us-east-1"],
        generated_at="now",
    )
    assert report.total == 2
    assert report.severity_counts["Critical"] == 1
    assert report.status_counts["fail"] == 1
    assert report.status_counts["pass"] == 1
    assert len(report.top_risks) == 1  # only the failing one
    assert report.top_risks[0].severity is Severity.CRITICAL
    names = {s.name: s.status for s in report.scanners}
    assert names["ash"] == "skipped"
