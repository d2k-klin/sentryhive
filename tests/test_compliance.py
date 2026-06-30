from sentryhive.aggregate import build_report, compliance_posture, iam_highlights
from sentryhive.models import Finding, Severity, framework_of
from sentryhive.scanners.base import ScanResult, ScanStatus


def test_framework_of_recognizes_known_frameworks():
    assert framework_of("CIS:2.1.5") == "CIS"
    assert framework_of("CIS-1.16") == "CIS"
    assert framework_of("PCI-DSS:8.3") == "PCI-DSS"
    assert framework_of("pci:1.2") == "PCI-DSS"
    assert framework_of("NIST:SC-7") == "NIST 800-53"
    assert framework_of("SOC2:CC6.1") == "SOC 2"


def test_framework_of_ignores_non_frameworks():
    assert framework_of("flagged-by:prowler+cloudsplaining") is None
    assert framework_of("CWE-798") is None
    assert framework_of("IAM-least-privilege") is None
    assert framework_of("EKS-best-practices") is None
    assert framework_of("") is None


def test_finding_frameworks_set():
    f = Finding(
        tool="prowler",
        check="c",
        title="t",
        description="d",
        compliance_refs=["CIS:2.1.5", "NIST:SC-7", "flagged-by:a+b"],
    )
    assert f.frameworks() == {"CIS", "NIST 800-53"}


def test_compliance_posture_counts_pass_and_fail():
    findings = [
        Finding(
            tool="prowler",
            check="a",
            title="t",
            description="d",
            status="fail",
            resource="r1",
            compliance_refs=["CIS:1.1"],
        ),
        Finding(
            tool="prowler",
            check="b",
            title="t",
            description="d",
            status="pass",
            resource="r2",
            compliance_refs=["CIS:1.2"],
        ),
        Finding(
            tool="prowler",
            check="c",
            title="t",
            description="d",
            status="pass",
            resource="r3",
            compliance_refs=["PCI-DSS:8.3"],
        ),
    ]
    posture = {p.framework: p for p in compliance_posture(findings)}
    assert posture["CIS"].passed == 1 and posture["CIS"].failed == 1
    assert posture["CIS"].pass_pct == 50
    assert posture["PCI-DSS"].pass_pct == 100


def test_iam_highlights_surfaces_priv_esc():
    findings = [
        Finding(
            tool="cloudsplaining",
            check="PrivilegeEscalation",
            title="priv esc: Role",
            description="d",
            severity=Severity.HIGH,
            service="iam",
            resource="Role",
            status="fail",
        ),
        Finding(
            tool="prowler",
            check="s3_public",
            title="public bucket",
            description="d",
            severity=Severity.CRITICAL,
            service="s3",
            resource="b",
            status="fail",
        ),
    ]
    highlights = iam_highlights(findings)
    assert len(highlights) == 1
    assert highlights[0].tool == "cloudsplaining"


def test_build_report_populates_consultant_fields():
    results = [
        ScanResult(
            "prowler",
            ScanStatus.OK,
            version="prowler 4.0",
            findings=[
                Finding(
                    tool="prowler",
                    check="a",
                    title="t",
                    description="d",
                    status="fail",
                    severity=Severity.HIGH,
                    resource="r1",
                    compliance_refs=["CIS:1.1"],
                ),
            ],
        )
    ]
    report = build_report(
        results,
        account_id="123",
        identity_arn="arn",
        regions=["us-east-1"],
        generated_at="now",
        client_name="Acme Corp",
    )
    assert report.client_name == "Acme Corp"
    assert report.scanners[0].version == "prowler 4.0"
    assert any(c.framework == "CIS" for c in report.compliance)
