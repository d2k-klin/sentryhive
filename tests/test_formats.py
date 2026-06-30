import importlib.util

import pytest

from sentryhive.aggregate import build_report
from sentryhive.models import Finding, Severity
from sentryhive.report import VALID_FORMATS, PdfError, render_pdf, write_reports
from sentryhive.report.generator import render_html
from sentryhive.scanners.base import ScanResult, ScanStatus

_WEASY = importlib.util.find_spec("weasyprint") is not None


def _report():
    results = [
        ScanResult(
            "prowler",
            ScanStatus.OK,
            findings=[
                Finding(
                    tool="prowler",
                    check="s3_public",
                    title="S3 public",
                    description="d",
                    severity=Severity.CRITICAL,
                    service="s3",
                    resource="b",
                    status="fail",
                    compliance_refs=["CIS:2.1.5"],
                ),
            ],
        )
    ]
    return build_report(
        results,
        account_id="123",
        identity_arn="arn",
        regions=["us-east-1"],
        generated_at="now",
        client_name="Acme Corp",
    )


def test_valid_formats_set():
    assert VALID_FORMATS == {"html", "md", "json", "pdf"}


def test_selective_formats_only_writes_requested(tmp_path):
    paths = write_reports(_report(), str(tmp_path), formats=["json"])
    assert set(paths) == {"json"}
    assert not (tmp_path / "report.html").exists()


def test_html_has_print_cover_and_scope(tmp_path):
    html = render_html(_report())
    # PDF front matter is embedded (hidden on screen, shown in print).
    assert "CONFIDENTIAL" in html
    assert "Scope &amp; methodology" in html or "Scope & methodology" in html
    assert "@media print" in html


def test_pdf_missing_engine_is_graceful(tmp_path):
    # Whether or not weasyprint is installed, requesting pdf must never raise here.
    paths = write_reports(_report(), str(tmp_path), formats=["html", "pdf"])
    assert "html" in paths
    if _WEASY:
        assert "pdf" in paths and (tmp_path / "report.pdf").exists()
    else:
        assert "pdf" not in paths


def test_chromium_engine_without_binary_raises(monkeypatch):
    monkeypatch.setattr("shutil.which", lambda _: None)
    with pytest.raises(PdfError):
        render_pdf("<html></html>", "/tmp/x.pdf", engine="chromium")


@pytest.mark.skipif(not _WEASY, reason="weasyprint not installed")
def test_weasyprint_renders_pdf(tmp_path):
    out = tmp_path / "r.pdf"
    render_pdf(render_html(_report()), str(out), engine="weasyprint")
    assert out.exists() and out.stat().st_size > 0
    assert out.read_bytes()[:4] == b"%PDF"
