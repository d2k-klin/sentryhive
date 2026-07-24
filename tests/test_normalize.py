from sentryhive.models import Severity
from sentryhive.normalize import (
    parse_ash,
    parse_cloudfox,
    parse_cloudsplaining,
    parse_hardeneks,
    parse_kubescape,
    parse_prowler,
)


def test_parse_prowler_ocsf():
    raw = [
        {
            "severity": "High",
            "status_code": "FAIL",
            "finding_info": {
                "uid": "s3_bucket_public",
                "title": "S3 bucket is public",
                "desc": "Bucket allows public reads",
            },
            "resources": [{"uid": "arn:aws:s3:::my-bucket", "region": "us-east-1", "group": {"name": "s3"}}],
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


def test_parse_cloudsplaining_native_results():
    raw = {
        "customer_managed_policies": {
            "policy-1": {
                "PolicyName": "PowerUserPolicy",
                "Arn": "arn:aws:iam::123456789012:policy/PowerUserPolicy",
                "PrivilegeEscalation": {
                    "severity": "high",
                    "description": "<p>Privilege escalation path</p>",
                    "findings": [{"type": "CreateAccessKey", "actions": ["iam:CreateAccessKey"]}],
                },
                "ServiceWildcard": {"severity": "medium", "description": "", "findings": ["s3:*"]},
            }
        },
        "inline_policies": {},
        "aws_managed_policies": {},
    }

    findings = parse_cloudsplaining(raw, account_id="123456789012")

    assert len(findings) == 2
    assert {f.check for f in findings} == {"PrivilegeEscalation", "ServiceWildcard"}
    assert all(f.resource == "arn:aws:iam::123456789012:policy/PowerUserPolicy" for f in findings)
    assert all(f.account_id == "123456789012" for f in findings)
    assert any(f.severity is Severity.HIGH for f in findings)


def test_parse_hardeneks():
    raw = {
        "findings": [
            {
                "rule": "disable_anonymous_access",
                "title": "Anonymous access enabled",
                "severity": "high",
                "namespace": "kube-system",
                "remediation": "Remove the binding",
            }
        ]
    }
    f = parse_hardeneks(raw, account_id="123456789012", region="eu-central-1")[0]
    assert f.tool == "hardeneks"
    assert f.service == "eks"
    assert f.region == "eu-central-1"
    assert f.severity is Severity.HIGH


def test_parse_cloudfox_separates_risks_from_observations():
    raw = {
        "workloads": [
            {
                "Account": "123456789012",
                "Service": "Lambda",
                "Region": "eu-central-1",
                "Arn": "arn:aws:lambda:eu-central-1:123456789012:function:admin",
                "Role": "arn:aws:iam::123456789012:role/Admin",
                "IsAdminRole?": "YES",
                "CanPrivEscToAdmin?": "No",
            }
        ],
        "role-trusts-principals-root-trusts-without-external-id": [
            {
                "Account": "123456789012",
                "Role Arn": "arn:aws:iam::123456789012:role/Vendor",
                "Trusted Principal": "arn:aws:iam::999999999999:root",
            }
        ],
        "endpoints": [
            {
                "Account": "123456789012",
                "Service": "ELB",
                "Region": "eu-central-1",
                "Endpoint": "public.example.com",
                "Port": "443",
                "Protocol": "https",
                "Public": "Yes",
            }
        ],
    }

    findings = parse_cloudfox(raw)

    assert len(findings) == 3
    assert [f.status for f in findings].count("fail") == 2
    assert [f.status for f in findings].count("info") == 1
    assert any(f.check == "root-trust-without-external-id" for f in findings)


def test_parse_kubescape_v2_groups_resources_per_control():
    raw = {
        "clusterName": "prod",
        "summaryDetails": {
            "controls": {
                "C-0057": {
                    "controlID": "C-0057",
                    "name": "Privileged container",
                    "statusInfo": {"status": "failed"},
                    "severity": "Critical",
                    "ResourceCounters": {"failedResources": 2, "passedResources": 4},
                },
                "C-0005": {
                    "controlID": "C-0005",
                    "name": "API server insecure port",
                    "statusInfo": {"status": "passed"},
                    "scoreFactor": 9,
                    "ResourceCounters": {"failedResources": 0, "passedResources": 1},
                },
            },
            "frameworks": [
                {
                    "name": "CIS",
                    "controls": {
                        "C-0057": {"controlID": "C-0057"},
                        "C-0005": {"controlID": "C-0005"},
                    },
                }
            ],
        },
        "results": [
            {
                "resourceID": "/apps/v1/default/Deployment/api",
                "controls": [{"controlID": "C-0057", "status": {"status": "failed"}}],
            },
            {
                "resourceID": "/apps/v1/default/Deployment/worker",
                "controls": [{"controlID": "C-0057", "status": {"status": "failed"}}],
            },
        ],
    }

    findings = parse_kubescape(raw, cluster="prod", account_id="123", region="eu-central-1")

    assert len(findings) == 2
    failed = next(f for f in findings if f.check == "C-0057")
    assert failed.status == "fail"
    assert failed.severity is Severity.CRITICAL
    assert "2 affected" in failed.resource
    assert "Deployment/api" in failed.description
    assert failed.compliance_refs == ["CIS:C-0057"]
    assert next(f for f in findings if f.check == "C-0005").status == "pass"


def test_parse_ash():
    raw = {
        "findings": [
            {
                "rule_id": "CKV_AWS_18",
                "title": "S3 access logging disabled",
                "severity": "medium",
                "file_path": "main.tf",
                "line": 12,
                "scanner": "checkov",
                "remediation": "Enable logging",
            }
        ]
    }
    f = parse_ash(raw)[0]
    assert f.tool == "ash"
    assert f.resource == "main.tf:12"
    assert f.service == "checkov"
    assert f.severity is Severity.MEDIUM


def test_parse_ash_v3_sarif():
    result = {
        "ruleId": "CKV_AWS_18",
        "level": "warning",
        "message": {"text": "S3 bucket access logging is disabled"},
        "locations": [
            {
                "physicalLocation": {
                    "artifactLocation": {"uri": "infra/main.tf"},
                    "region": {"startLine": 42},
                }
            }
        ],
        "properties": {"scanner_name": "checkov"},
    }
    suppressed = {**result, "ruleId": "SUPPRESSED", "suppressions": [{"kind": "external"}]}
    findings = parse_ash({"sarif": {"runs": [{"results": [result, suppressed]}]}})

    assert len(findings) == 1
    f = findings[0]
    assert f.check == "CKV_AWS_18"
    assert f.description == "S3 bucket access logging is disabled"
    assert f.resource == "infra/main.tf:42"
    assert f.service == "checkov"
    assert f.severity is Severity.MEDIUM


def test_parsers_tolerate_garbage():
    assert parse_prowler([{"unexpected": "shape"}])  # does not raise
    assert parse_ash({"findings": ["not a dict", 5, None]}) == []
    assert parse_cloudsplaining({"results": {"P": "not-a-dict"}}) == []
