import pytest
import typer
from typer.testing import CliRunner

from sentryhive import cli
from sentryhive.models import Finding, Severity
from sentryhive.scanners.base import ScanResult, ScanStatus
from sentryhive.scanners.hardeneks import HardeneksScanner
from sentryhive.scanners.kubescape import KubescapeScanner


def _ctx(account_id):
    """Minimal stand-in for a verified AwsContext."""

    class _Identity:
        def __init__(self, acct):
            self.account_id = acct
            self.arn = f"arn:aws:iam::{acct}:role/audit [bracketed]"
            self.user_id = "AIDA"

    class _Ctx:
        def __init__(self, acct):
            self.identity = _Identity(acct)
            self.regions = ["eu-west-1"]

    return _Ctx(account_id)


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
    monkeypatch.setattr(cli, "build_scanners", lambda _names, **_kwargs: [object()])
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


def test_scanner_messages_with_brackets_do_not_crash_the_console(capsys):
    """Regression: rich parsed a loot path in a scanner message as markup and raised.

    The real message contained
    '[/tmp/sentryhive-.../loot/endpoints-UrlsOnly.txt]', which rich read as a closing
    tag with no opening tag, killing the whole run after the scan had already succeeded.
    """
    from sentryhive.scanners.base import ScanResult, ScanStatus

    hostile = (
        "3 of 5 modules completed; failed — endpoints: crashed — killed by SIGSEGV "
        "(signal 11) — wrote [/tmp/sentryhive-432m02ux/cloudfox/cloudfox-output/aws/"
        "254038622216-AIDATWJPBYAEK4P5IOHDM/loot/endpoints-UrlsOnly.txt] [bold] [/red]"
    )

    class _Scanner:
        name = "cloudfox"
        show_scanner_output = False

        def run(self, ctx, workdir):
            return ScanResult("cloudfox", ScanStatus.ERROR, message=hostile)

    results = cli._run([_Scanner()], None, "/tmp")

    out = capsys.readouterr().out
    assert results[0].status is ScanStatus.ERROR
    assert "UrlsOnly.txt" in out  # printed literally, not swallowed as markup
    assert "error" in out


def test_incomplete_scan_summary_survives_bracket_text(capsys):
    """The same hostile message reaching the exit-code path must not crash either."""
    from sentryhive.aggregate import ScannerSummary

    class _Report:
        scanner_errors = [ScannerSummary("cloudfox", "error", 0, "wrote [/tmp/loot/x.txt] [/red]")]

    with pytest.raises(typer.Exit) as exc:
        cli._fail_on_scanner_errors([_Report()])

    assert exc.value.exit_code == 1
    assert "x.txt" in capsys.readouterr().out


def test_scan_end_to_end_with_hostile_scanner_output(monkeypatch, tmp_path):
    """Full CLI run with scanner output engineered to break the console and the report.

    Every console-crash regression so far reached users because the unit tests exercised
    scanners and templates in isolation, never `scan` end to end. This drives the real
    command and asserts it survives brackets, rich markup, ANSI and control characters
    in scanner-controlled strings, then writes readable reports.
    """
    hostile_message = (
        "[endpoints][acct] Loot written to [/tmp/sentryhive-x/loot/endpoints-UrlsOnly.txt] "
        "[/red] [bold]unclosed \x1b[31m ansi \x00 null"
    )
    hostile_finding = Finding(
        tool="cloudfox",
        check="[check]",
        title="Public endpoint [/bold] <script>alert(1)</script>",
        description="resource [/dim] & <b>markup</b>",
        severity=Severity.HIGH,
        service="ec2",
        resource="arn:aws:ec2:eu-west-1:1:instance/[i-123]",
        status="fail",
        compliance_refs=["CIS:1.1"],
    )

    monkeypatch.setattr(cli, "build_contexts", lambda **_kw: [_ctx("254038622216")])
    monkeypatch.setattr(
        cli,
        "_run",
        lambda *_a, **_kw: [
            ScanResult("cloudfox", ScanStatus.ERROR, findings=[hostile_finding], message=hostile_message),
            ScanResult("resilience", ScanStatus.OK, findings=[], message=""),
        ],
    )

    result = CliRunner().invoke(
        cli.app,
        ["scan", "--role-arn", "arn::254038622216", "--yes", "--out", str(tmp_path), "--format", "html,md,json"],
    )

    # Exit 1 for incomplete evidence — but a clean exit, not a traceback.
    assert result.exit_code == 1, result.output
    assert result.exception is None or isinstance(result.exception, SystemExit)
    assert "Traceback" not in result.output
    assert "MarkupError" not in result.output
    assert "UrlsOnly.txt" in result.output

    html = (tmp_path / "report.html").read_text()
    assert "<script>alert(1)</script>" not in html  # escaped, not injected
    assert "Public endpoint" in html
    assert (tmp_path / "report.md").exists()
    assert (tmp_path / "findings.json").exists()
