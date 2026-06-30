from sentryhive.models import Finding, Severity


def test_severity_parse_variants():
    assert Severity.parse("CRITICAL") is Severity.CRITICAL
    assert Severity.parse("warning") is Severity.MEDIUM
    assert Severity.parse("informational") is Severity.INFO
    assert Severity.parse(None) is Severity.INFO
    assert Severity.parse(3) is Severity.HIGH
    assert Severity.parse("nonsense") is Severity.INFO


def test_severity_ordering():
    assert Severity.CRITICAL > Severity.HIGH > Severity.MEDIUM > Severity.LOW > Severity.INFO


def test_finding_autofills_id_and_coerces_severity():
    f = Finding(tool="prowler", check="c1", title="t", description="d", severity="high",
                resource="arn:aws:s3:::bucket")
    assert f.severity is Severity.HIGH
    assert f.id and len(f.id) == 12
    # Stable fingerprint.
    f2 = Finding(tool="prowler", check="c1", title="x", description="y", resource="arn:aws:s3:::bucket")
    assert f.id == f2.id


def test_dedup_key_ignores_tool():
    a = Finding(tool="prowler", check="public", title="t", description="d",
                service="s3", resource="b")
    b = Finding(tool="cloudsplaining", check="public", title="t", description="d",
                service="s3", resource="b")
    assert a.dedup_key == b.dedup_key


def test_to_dict_includes_severity_label_and_rank():
    f = Finding(tool="ash", check="c", title="t", description="d", severity=Severity.LOW)
    d = f.to_dict()
    assert d["severity"] == "Low"
    assert d["severity_rank"] == int(Severity.LOW)
