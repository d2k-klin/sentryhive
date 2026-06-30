"""Golden-file report test.

Renders a report from a fixed set of findings and compares against a committed
'expected' output. This catches accidental report template regressions.

To update the golden file after an intentional change:
    pytest tests/test_golden_report.py --update-golden
"""

import pathlib

import pytest

from sentryhive.aggregate import build_report
from sentryhive.models import Finding, Severity
from sentryhive.report.generator import render_md
from sentryhive.scanners.base import ScanResult, ScanStatus

GOLDEN_DIR = pathlib.Path(__file__).parent / "fixtures" / "golden"
GOLDEN_FILE = GOLDEN_DIR / "report.expected.md"


def _fixed_report():
    """Deterministic report for golden-file comparison."""
    results = [
        ScanResult(
            "prowler",
            ScanStatus.OK,
            version="prowler 4.6.0",
            findings=[
                Finding(
                    tool="prowler",
                    check="iam_root_mfa_enabled",
                    title="Root account does not have MFA enabled",
                    description="The root account has no MFA device configured.",
                    severity=Severity.CRITICAL,
                    service="iam",
                    resource="arn:aws:iam::123456789012:root",
                    region="us-east-1",
                    status="fail",
                    remediation="Enable a hardware or virtual MFA device.",
                    compliance_refs=["CIS:1.5", "PCI-DSS:8.3.1"],
                    account_id="123456789012",
                ),
                Finding(
                    tool="prowler",
                    check="s3_bucket_public_access",
                    title="S3 bucket allows public access",
                    description="The bucket ACL permits unauthenticated reads.",
                    severity=Severity.HIGH,
                    service="s3",
                    resource="arn:aws:s3:::example-public-assets",
                    region="eu-central-1",
                    status="fail",
                    remediation="Enable S3 Block Public Access.",
                    compliance_refs=["CIS:2.1.5"],
                    account_id="123456789012",
                ),
            ],
        ),
        ScanResult(
            "cloudsplaining",
            ScanStatus.OK,
            version="cloudsplaining 0.7.0",
            findings=[
                Finding(
                    tool="cloudsplaining",
                    check="PrivilegeEscalation",
                    title="Privilege escalation path: AdminPolicy",
                    description="Policy 'AdminPolicy' grants: iam:CreateAccessKey",
                    severity=Severity.HIGH,
                    service="iam",
                    resource="AdminPolicy",
                    status="fail",
                    remediation="Apply least privilege: remove the flagged actions.",
                    compliance_refs=["CIS-1.16", "IAM-least-privilege"],
                    account_id="123456789012",
                ),
            ],
        ),
    ]
    return build_report(
        results,
        account_id="123456789012",
        identity_arn="arn:aws:iam::123456789012:role/SecurityAudit",
        regions=["eu-central-1"],
        generated_at="2026-01-01 00:00:00 UTC",
        client_name="Golden Test Corp",
    )


@pytest.fixture
def update_golden(request):
    return request.config.getoption("--update-golden", default=False)


def test_markdown_matches_golden(update_golden, tmp_path):
    report = _fixed_report()
    actual = render_md(report)

    if update_golden or not GOLDEN_FILE.exists():
        GOLDEN_DIR.mkdir(parents=True, exist_ok=True)
        GOLDEN_FILE.write_text(actual)
        pytest.skip("Golden file updated/created.")

    expected = GOLDEN_FILE.read_text()
    if actual != expected:
        # Write actual for easy diff.
        actual_path = tmp_path / "report.actual.md"
        actual_path.write_text(actual)
        pytest.fail(
            f"Report output differs from golden file.\n"
            f"  Expected: {GOLDEN_FILE}\n"
            f"  Actual:   {actual_path}\n"
            f"Run with --update-golden to accept changes."
        )
