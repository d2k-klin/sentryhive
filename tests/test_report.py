import json

from sentryhive.aggregate import build_report
from sentryhive.models import Finding, Severity
from sentryhive.report import write_reports
from sentryhive.scanners.base import ScanResult, ScanStatus


def _sample_report():
    results = [
        ScanResult(
            "prowler",
            ScanStatus.OK,
            findings=[
                Finding(
                    tool="prowler",
                    check="s3_public",
                    title="S3 bucket public",
                    description="Bucket allows public reads",
                    severity=Severity.CRITICAL,
                    service="s3",
                    resource="arn:aws:s3:::demo",
                    region="us-east-1",
                    remediation="Block public access",
                    compliance_refs=["CIS:2.1.5"],
                ),
            ],
        ),
    ]
    return build_report(
        results,
        account_id="123456789012",
        identity_arn="arn:aws:iam::123456789012:user/auditor",
        regions=["us-east-1"],
        generated_at="2026-06-30 00:00:00 UTC",
    )


def test_write_reports_creates_all_three(tmp_path):
    paths = write_reports(_sample_report(), str(tmp_path))
    assert set(paths) == {"html", "md", "json"}
    for p in paths.values():
        assert (tmp_path / p.split("/")[-1]).exists()


def test_html_is_self_contained_and_has_findings(tmp_path):
    write_reports(_sample_report(), str(tmp_path))
    html = (tmp_path / "report.html").read_text()
    assert "<style>" in html  # inline CSS, no external assets
    assert "S3 bucket public" in html
    assert "123456789012" in html
    assert "OSS SentryHive" in html
    assert "Created by Mr. D" in html
    assert '<option value="fail" selected>Failures</option>' in html
    assert "Unified evidence register" in html


def test_html_escapes_scanner_controlled_text():
    report = _sample_report()
    report.findings[0].title = '<script>alert("x")</script>'
    report.findings[0].description = '<img src=x onerror="alert(1)">'

    from sentryhive.report.generator import render_html

    html = render_html(report)
    assert '<script>alert("x")</script>' not in html
    assert "&lt;script&gt;" in html
    assert "<img src=x" not in html


def test_json_is_machine_readable(tmp_path):
    write_reports(_sample_report(), str(tmp_path))
    data = json.loads((tmp_path / "findings.json").read_text())
    assert data["account_id"] == "123456789012"
    assert data["summary"]["by_severity"]["Critical"] == 1
    assert data["findings"][0]["tool"] == "prowler"


def test_markdown_has_summary(tmp_path):
    write_reports(_sample_report(), str(tmp_path))
    md = (tmp_path / "report.md").read_text()
    assert "SentryHive Security Report" in md
    assert "Top 1 risks" in md


def test_backup_and_recovery_section_renders_in_both_formats(tmp_path):
    """The section must gather evidence from the native scanner and the wrapped ones."""
    results = [
        ScanResult(
            "resilience",
            ScanStatus.OK,
            findings=[
                Finding(
                    tool="resilience",
                    check="resilience-restore-tested",
                    title="No restore completed in the last 90 days",
                    description="Backups exist but no restore job proves they are recoverable.",
                    severity=Severity.MEDIUM,
                    service="backup",
                    resource="eu-central-1",
                    compliance_refs=["SOC2:A1.3", "ISO-27001:A.5.30"],
                ),
            ],
        ),
        ScanResult(
            "prowler",
            ScanStatus.OK,
            findings=[
                Finding(
                    tool="prowler",
                    check="s3_bucket_object_versioning",
                    title="S3 bucket versioning disabled",
                    description="Objects can be overwritten irrecoverably",
                    severity=Severity.MEDIUM,
                    service="s3",
                    resource="arn:aws:s3:::demo",
                    compliance_refs=["CIS:2.1.2"],
                ),
            ],
        ),
    ]
    report = build_report(
        results,
        account_id="123456789012",
        identity_arn="arn:aws:iam::123456789012:user/auditor",
        regions=["eu-central-1"],
        generated_at="2026-06-30 00:00:00 UTC",
    )
    assert len(report.resilience_findings) == 2

    write_reports(report, str(tmp_path), formats=["html", "md"])
    html = (tmp_path / "report.html").read_text()
    md = (tmp_path / "report.md").read_text()

    for text in (html, md):
        assert "Backup &amp; recovery" in text or "Backup & recovery" in text
        assert "No restore completed" in text
        assert "S3 bucket versioning disabled" in text
    assert 'href="#resilience"' in html  # linked from the print contents page


def test_markdown_marks_incomplete_scan(tmp_path):
    report = build_report(
        [ScanResult("prowler", ScanStatus.ERROR, message="scanner timed out", version="Prowler 5.31.1")],
        account_id="123456789012",
        identity_arn="arn:aws:iam::123456789012:user/auditor",
        regions=["us-east-1"],
        generated_at="2026-06-30 00:00:00 UTC",
    )

    write_reports(report, str(tmp_path), formats=["md", "json"])

    md = (tmp_path / "report.md").read_text()
    data = json.loads((tmp_path / "findings.json").read_text())
    assert "Scan incomplete" in md
    assert "not a clean account" in md
    assert data["summary"]["scan_complete"] is False
