from sentryhive.aggregate import build_report
from sentryhive.models import Finding, Severity
from sentryhive.report import write_reports
from sentryhive.scanners.base import ScanStatus, session_env
from sentryhive.scanners.hardeneks import HardeneksScanner


def _eks_report(tmp_path):
    from sentryhive.scanners.base import ScanResult
    results = [ScanResult("hardeneks[prod-eks]", ScanStatus.OK, version="hardeneks 0.12", findings=[
        Finding(tool="hardeneks", check="disable_anonymous_access", title="Anonymous access",
                description="d", severity=Severity.HIGH, service="eks",
                resource="prod-eks/kube-system", region="eu-central-1"),
    ])]
    return build_report(results, account_id="123", identity_arn="arn", regions=["eu-central-1"],
                        generated_at="now")


def test_eks_findings_grouped_separately():
    rep = _eks_report(None)
    assert len(rep.eks_findings) == 1
    assert rep.account_findings == []  # only EKS findings present


def test_eks_section_renders_in_html(tmp_path):
    write_reports(_eks_report(tmp_path), str(tmp_path))
    html = (tmp_path / "report.html").read_text()
    assert "EKS Hardening" in html
    assert "prod-eks/kube-system" in html


def test_hardeneks_skips_without_cluster():
    h = HardeneksScanner(cluster=None)
    h.binary = ""  # mark available so we reach the no-cluster guard
    result = h.run(None, "/tmp")
    assert result.status is ScanStatus.SKIPPED
    assert "cluster" in result.message.lower()


def test_hardeneks_name_includes_cluster():
    h = HardeneksScanner(cluster="prod-eks")
    assert "prod-eks" in h.name


def test_preflight_reports_missing_kubectl(monkeypatch):
    h = HardeneksScanner(cluster="prod-eks")
    monkeypatch.setattr("shutil.which", lambda _: None)
    ok, detail = h._preflight(session_env(None))
    assert ok is False
    assert "kubectl" in detail
