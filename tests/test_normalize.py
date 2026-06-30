from sentryhive.models import Severity
from sentryhive.normalize import (
    parse_ash,
    parse_cloudsplaining,
    parse_hardeneks,
    parse_prowler,
)


def test_parse_prowler_ocsf():
    raw = [
        {
            "severity": "High",
            "status_code": "FAIL",
            "finding_info": {"uid": "s3_bucket_public", "title": "S3 bucket is public",
                              "desc": "Bucket allows public reads"},
            "resources": [{"uid": "arn:aws:s3:::my-bucket", "region": "us-east-1",
                            "group": {"name": "s3"}}],
            "remediation": {"desc": "Block public access"},
            "cloud": {"account": {"uid": "123456789012"}, "region": "us-east-1"},
            "unmapped": {"compliance": {"CIS": ["2.1.5"]}},
        }
    ]
    findings = parse_prowler(raw)
    assert len(findings) == 1
    f = findings[0]
    assert f.tool == "prowler"
    assert f.severity is Severity.HIGH
    assert f.status == "fail"
    assert f.service == "s3"
    assert f.resource == "arn:aws:s3:::my-bucket"
    assert "CIS:2.1.5" in f.compliance_refs
    assert f.account_id == "123456789012"


def test_parse_prowler_native_v3():
    raw = [
        {
            "Status": "FAIL",
            "Severity": "critical",
            "CheckID": "iam_root_mfa",
            "CheckTitle": "Root MFA disabled",
            "ServiceName": "iam",
            "ResourceId": "root",
            "Region": "us-east-1",
            "Remediation": {"Recommendation": {"Text": "Enable MFA on root"}},
            "Compliance": {"CIS": ["1.5"]},
            "AccountId": "123456789012",
        }
    ]
    f = parse_prowler(raw)[0]
    assert f.severity is Severity.CRITICAL
    assert f.check == "iam_root_mfa"
    assert f.remediation == "Enable MFA on root"
    assert "CIS:1.5" in f.compliance_refs


def test_parse_cloudsplaining():
    raw = {
        "results": {
            "AdminPolicy": {
                "PrivilegeEscalation": [{"type": "CreateAccessKey"}],
                "ResourceExposure": ["iam:PassRole"],
            }
        }
    }
    findings = parse_cloudsplaining(raw, account_id="123456789012")
    assert len(findings) == 2
    assert all(f.tool == "cloudsplaining" for f in findings)
    assert all(f.service == "iam" for f in findings)
    assert any(f.check == "PrivilegeEscalation" for f in findings)


def test_parse_hardeneks():
    raw = {
        "findings": [
            {"rule": "disable_anonymous_access", "title": "Anonymous access enabled",
             "severity": "high", "namespace": "kube-system",
             "remediation": "Remove the binding"}
        ]
    }
    f = parse_hardeneks(raw, account_id="123456789012", region="eu-central-1")[0]
    assert f.tool == "hardeneks"
    assert f.service == "eks"
    assert f.region == "eu-central-1"
    assert f.severity is Severity.HIGH


def test_parse_ash():
    raw = {
        "findings": [
            {"rule_id": "CKV_AWS_18", "title": "S3 access logging disabled",
             "severity": "medium", "file_path": "main.tf", "line": 12,
             "scanner": "checkov", "remediation": "Enable logging"}
        ]
    }
    f = parse_ash(raw)[0]
    assert f.tool == "ash"
    assert f.resource == "main.tf:12"
    assert f.service == "checkov"
    assert f.severity is Severity.MEDIUM


def test_parsers_tolerate_garbage():
    assert parse_prowler([{"unexpected": "shape"}])  # does not raise
    assert parse_ash({"findings": ["not a dict", 5, None]}) == []
    assert parse_cloudsplaining({"results": {"P": "not-a-dict"}}) == []
