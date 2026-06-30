from sentryhive.aggregate import build_report, build_rollup
from sentryhive.models import Finding, Severity
from sentryhive.report import write_reports
from sentryhive.scanners.base import ScanResult, ScanStatus


def _account_report(account_id, sev):
    results = [ScanResult("prowler", ScanStatus.OK, findings=[
        Finding(tool="prowler", check="root_mfa", title="Root MFA disabled", description="d",
                severity=sev, service="iam", resource="root", status="fail",
                compliance_refs=["CIS:1.5"], account_id=account_id),
    ])]
    return build_report(results, account_id=account_id, identity_arn=f"arn::{account_id}",
                        regions=["us-east-1"], generated_at="now")


def test_rollup_combines_accounts_without_cross_account_dedup():
    a = _account_report("111111111111", Severity.HIGH)
    b = _account_report("222222222222", Severity.CRITICAL)
    rollup = build_rollup([a, b], generated_at="now", client_name="Acme Corp")
    assert rollup.is_rollup is True
    assert rollup.accounts == ["111111111111", "222222222222"]
    # Same resource ("root") in two different accounts stays distinct.
    assert rollup.total == 2
    assert rollup.severity_counts["Critical"] == 1
    assert rollup.severity_counts["High"] == 1
    assert rollup.client_name == "Acme Corp"


def test_rollup_renders_html(tmp_path):
    a = _account_report("111111111111", Severity.HIGH)
    b = _account_report("222222222222", Severity.CRITICAL)
    rollup = build_rollup([a, b], generated_at="now")
    write_reports(rollup, str(tmp_path))
    html = (tmp_path / "report.html").read_text()
    assert "111111111111" in html and "222222222222" in html
    assert "Compliance posture" in html


def test_branding_appears_in_html(tmp_path):
    rep = _account_report("123456789012", Severity.HIGH)
    rep.client_name = "Acme Corp"
    rep.logo_data_uri = "data:image/png;base64,AAAA"
    write_reports(rep, str(tmp_path))
    html = (tmp_path / "report.html").read_text()
    assert "Acme Corp" in html
    assert "data:image/png;base64,AAAA" in html
