import pytest
import typer
from typer.testing import CliRunner

from sentryhive import cli
from sentryhive.models import Finding, Severity
from sentryhive.scanners.base import ScanResult, ScanStatus
from sentryhive.scanners.hardeneks import HardeneksScanner
from sentryhive.scanners.kubescape import KubescapeScanner


def test_kubernetes_disabled_does_not_discover_clusters(monkeypatch):
    def unexpected_discovery(_ctx):
        raise AssertionError("cluster discovery must stay off")

    monkeypatch.setattr(cli, "discover_eks_clusters", unexpected_discovery)

    assert cli._kubernetes_scanners(object(), False, [], None, None) == []


def test_kubernetes_default_builds_both_scanners(monkeypatch):
    monkeypatch.setattr(cli, "discover_eks_clusters", lambda _ctx: ["prod"])

    scanners = cli._kubernetes_scanners(object(), True, [], None, "/tmp/kubeconfig")

    assert [type(scanner) for scanner in scanners] == [HardeneksScanner, KubescapeScanner]
    assert all(scanner.cluster == "prod" for scanner in scanners)


def test_kubernetes_request_without_clusters_stays_in_evidence(monkeypatch):
    monkeypatch.delenv("SENTRYHIVE_EKS_CLUSTER", raising=False)
    monkeypatch.setattr(cli, "discover_eks_clusters", lambda _ctx: [])

    scanners = cli._kubernetes_scanners(object(), True, [], None, None)

    assert [type(scanner) for scanner in scanners] == [HardeneksScanner, KubescapeScanner]
    assert all(scanner.cluster is None for scanner in scanners)


def test_resolve_formats_adds_pdf_once():
    assert cli._resolve_formats("html,json", pdf=True) == ["html", "json", "pdf"]
    assert cli._resolve_formats("html,pdf", pdf=True) == ["html", "pdf"]


def test_resolve_formats_rejects_unknown():
    with pytest.raises(typer.Exit) as exc:
        cli._resolve_formats("html,xml", pdf=False)
    assert exc.value.exit_code == 2


def test_multi_account_scan_writes_one_combined_report(monkeypatch, tmp_path):
    contexts = [
        type(
            "Context",
            (),
            {
                "identity": type("Identity", (), {"account_id": account, "arn": f"arn::{account}"})(),
                "regions": ["us-east-1"],
            },
        )()
        for account in ("111111111111", "222222222222")
    ]
    written = []

    monkeypatch.setattr(cli, "build_contexts", lambda **_kwargs: contexts)
    monkeypatch.setattr(cli, "build_scanners", lambda _names: [object()])
    monkeypatch.setattr(cli, "_confirm", lambda *_args: None)

    def fake_run(_scanners, ctx, _workdir, scanner_output=False):
        account = ctx.identity.account_id
        return [
            ScanResult(
                "prowler",
                ScanStatus.OK,
                findings=[
                    Finding(
                        tool="prowler",
                        check="root_mfa",
                        title="Root MFA",
                        description="test",
                        severity=Severity.HIGH,
                        resource=f"arn::{account}:root",
                        account_id=account,
                    )
                ],
            )
        ]

    monkeypatch.setattr(cli, "_run", fake_run)
    monkeypatch.setattr(
        cli,
        "write_reports",
        lambda report, out_dir, **_kwargs: written.append((report, out_dir)) or {"html": f"{out_dir}/report.html"},
    )
    monkeypatch.setattr(cli, "_print_summary", lambda *_args: None)

    result = CliRunner().invoke(
        cli.app,
        [
            "scan",
            "--role-arn",
            "arn::111111111111",
            "--role-arn",
            "arn::222222222222",
            "--yes",
            "--out",
            str(tmp_path),
        ],
    )

    assert result.exit_code == 0
    assert len(written) == 1
    report, out_dir = written[0]
    assert report.is_rollup is True
    assert report.accounts == ["111111111111", "222222222222"]
    assert out_dir == str(tmp_path)
