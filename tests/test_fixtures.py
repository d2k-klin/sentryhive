"""Integration test: parse fixture files through normalize → aggregate → report pipeline.

These tests use the sanitized scanner output committed under tests/fixtures/ to verify
the full normalizer → aggregator → report path end-to-end, without any live AWS calls.
"""

import json
import pathlib

from sentryhive.aggregate import build_report
from sentryhive.models import Severity
from sentryhive.normalize import parse_ash, parse_cloudsplaining, parse_hardeneks, parse_prowler
from sentryhive.report import write_reports
from sentryhive.scanners.base import ScanResult, ScanStatus

FIXTURES = pathlib.Path(__file__).parent / "fixtures"


def _load(name: str):
    with open(FIXTURES / name) as f:
        return json.load(f)


class TestProwlerFixture:
    def test_parse_returns_findings(self):
        findings = parse_prowler(_load("prowler_sample.json"))
        assert len(findings) == 5

    def test_severities_mapped(self):
        findings = parse_prowler(_load("prowler_sample.json"))
        sevs = {f.severity for f in findings}
        assert Severity.CRITICAL in sevs
        assert Severity.HIGH in sevs

    def test_account_id_populated(self):
        findings = parse_prowler(_load("prowler_sample.json"))
        assert all(f.account_id == "123456789012" for f in findings)

    def test_compliance_refs_present(self):
        findings = parse_prowler(_load("prowler_sample.json"))
        all_refs = [ref for f in findings for ref in f.compliance_refs]
        assert any("CIS" in r for r in all_refs)


class TestCloudsplainingFixture:
    def test_parse_returns_findings(self):
        findings = parse_cloudsplaining(_load("cloudsplaining_sample.json"), account_id="123456789012")
        # AdminPolicy has PrivilegeEscalation, DataExfiltration, ResourceExposure = 3
        # DeveloperPolicy has CredentialsExposure, ServiceWildcard = 2
        assert len(findings) == 5

    def test_only_risky_policies_flagged(self):
        findings = parse_cloudsplaining(_load("cloudsplaining_sample.json"))
        resources = {f.resource for f in findings}
        assert "ReadOnlyPolicy" not in resources

    def test_all_iam_service(self):
        findings = parse_cloudsplaining(_load("cloudsplaining_sample.json"))
        assert all(f.service == "iam" for f in findings)


class TestHardeneksFixture:
    def test_parse_returns_findings(self):
        findings = parse_hardeneks(_load("hardeneks_sample.json"), account_id="123456789012", region="eu-central-1")
        assert len(findings) == 4

    def test_eks_service(self):
        findings = parse_hardeneks(_load("hardeneks_sample.json"))
        assert all(f.service == "eks" for f in findings)

    def test_severities(self):
        findings = parse_hardeneks(_load("hardeneks_sample.json"))
        sevs = [f.severity for f in findings]
        assert sevs.count(Severity.HIGH) == 2
        assert sevs.count(Severity.MEDIUM) == 2


class TestAshFixture:
    def test_parse_returns_findings(self):
        findings = parse_ash(_load("ash_sample.json"))
        assert len(findings) == 4

    def test_resource_includes_file_and_line(self):
        findings = parse_ash(_load("ash_sample.json"))
        assert any("main.tf:42" in f.resource for f in findings)

    def test_critical_secret_detection(self):
        findings = parse_ash(_load("ash_sample.json"))
        secrets = [f for f in findings if f.severity is Severity.CRITICAL]
        assert len(secrets) == 1
        assert "key" in secrets[0].title.lower()


class TestEndToEndFromFixtures:
    """Full pipeline: fixtures → normalize → aggregate → report output."""

    def test_combined_report(self, tmp_path):
        prowler_findings = parse_prowler(_load("prowler_sample.json"))
        cloud_findings = parse_cloudsplaining(_load("cloudsplaining_sample.json"), account_id="123456789012")
        hardeneks_findings = parse_hardeneks(
            _load("hardeneks_sample.json"), account_id="123456789012", region="eu-central-1"
        )

        results = [
            ScanResult("prowler", ScanStatus.OK, findings=prowler_findings, version="prowler 4.6.0"),
            ScanResult("cloudsplaining", ScanStatus.OK, findings=cloud_findings, version="cloudsplaining 0.7.0"),
            ScanResult("hardeneks", ScanStatus.OK, findings=hardeneks_findings, version="hardeneks 0.12.0"),
        ]

        report = build_report(
            results,
            account_id="123456789012",
            identity_arn="arn:aws:iam::123456789012:role/SecurityAudit",
            regions=["eu-central-1"],
            generated_at="2026-06-30 12:00:00 UTC",
            client_name="Test Corp",
        )

        assert report.total > 0
        assert report.severity_counts["Critical"] >= 1
        assert len(report.scanners) == 3
        assert report.client_name == "Test Corp"

        # Write all formats and verify they're well-formed.
        paths = write_reports(report, str(tmp_path), formats=["html", "md", "json"])
        assert "html" in paths
        assert "md" in paths
        assert "json" in paths

        # JSON output is valid and contains expected structure.
        json_data = json.loads((tmp_path / "findings.json").read_text())
        assert json_data["account_id"] == "123456789012"
        assert json_data["summary"]["total"] == report.total
        assert len(json_data["findings"]) == report.total

        # HTML is self-contained.
        html = (tmp_path / "report.html").read_text()
        assert "<style>" in html
        assert "Test Corp" in html
        assert "123456789012" in html
