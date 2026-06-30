"""SentryHive command-line interface.

Tuned for the security-consultant / auditor workflow: cross-account assume-role is
the primary auth path, several client accounts can be scanned in one run, and the
output is an evidence-grade, optionally client-branded report (HTML/MD/JSON/PDF).

EKS hardening is a deliberately separate, opt-in phase (`--eks`): unlike the
IAM-only scanners it needs in-cluster RBAC access, so it is never bundled silently
into the default flow.
"""

from __future__ import annotations

import base64
import datetime as dt
import mimetypes
import os
import sys
import tempfile

import typer
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from sentryhive import __version__
from sentryhive.aggregate import build_report, build_rollup
from sentryhive.auth import AuthError, build_contexts, discover_eks_clusters
from sentryhive.report import VALID_FORMATS, write_reports
from sentryhive.scanners import ALL_SCANNERS, build_scanners
from sentryhive.scanners.ash import AshScanner
from sentryhive.scanners.base import Scanner
from sentryhive.scanners.hardeneks import HardeneksScanner

#: Default scanners for the consultant audience: compliance + IAM risk (addendum §2).
CORE_SCANNERS = ["prowler", "cloudsplaining"]
DEFAULT_FORMATS = ["html", "md", "json"]

app = typer.Typer(
    add_completion=False,
    help="Point SentryHive at one or more AWS accounts and get an evidence-grade security report.",
)
console = Console()


def _version_callback(value: bool):
    if value:
        console.print(f"SentryHive {__version__}")
        raise typer.Exit()


@app.callback()
def main(
    _version: bool = typer.Option(
        False,
        "--version",
        callback=_version_callback,
        is_eager=True,
        help="Show version and exit.",
    ),
):
    """SentryHive — AWS security scanning toolkit."""


@app.command()
def scanners():
    """List available scanners."""
    table = Table(title="Available scanners")
    table.add_column("Name")
    table.add_column("Role")
    table.add_column("Target")
    table.add_row("prowler", "core", "live AWS account — config & compliance")
    table.add_row("cloudsplaining", "core", "live AWS account — IAM policy risk")
    table.add_row("hardeneks", "opt-in (--eks)", "inside EKS cluster(s) — needs RBAC access")
    table.add_row("ash", "opt-in (--scanners)", "local code/IaC on disk")
    console.print(table)


@app.command()
def scan(
    profile: str = typer.Option(None, "--profile", help="AWS profile name."),
    role_arn: list[str] = typer.Option(
        None,
        "--role-arn",
        help="IAM role ARN to assume (STS). Repeat for multi-account scans.",
    ),
    external_id: str = typer.Option(None, "--external-id", help="External ID for role assumption."),
    regions: str = typer.Option(None, "--regions", help="Comma-separated regions (e.g. eu-central-1,us-east-1)."),
    scanners_opt: str = typer.Option(
        ",".join(CORE_SCANNERS),
        "--scanners",
        help=f"Comma-separated account scanners. Core: {', '.join(CORE_SCANNERS)}. "
        "Add 'ash' for local IaC. (EKS hardening is enabled with --eks.)",
    ),
    eks: bool = typer.Option(False, "--eks", help="Run EKS hardening (opt-in; needs in-cluster RBAC access)."),
    clusters: str = typer.Option(None, "--clusters", help="Comma-separated EKS clusters (default: all detected)."),
    kubeconfig: str = typer.Option(None, "--kubeconfig", help="Path to a kubeconfig for EKS access."),
    source_dir: str = typer.Option(None, "--source-dir", help="Directory ASH scans (defaults to CWD)."),
    client_name: str = typer.Option(None, "--client-name", help="Client/engagement name for the report header."),
    logo: str = typer.Option(None, "--logo", help="Path to a logo image embedded in the report header."),
    output_formats: str = typer.Option(
        ",".join(DEFAULT_FORMATS),
        "--format",
        help="Comma-separated output formats: html, md, json, pdf.",
    ),
    pdf: bool = typer.Option(False, "--pdf", help="Shorthand to add PDF output (the client deliverable)."),
    pdf_engine: str = typer.Option("weasyprint", "--pdf-engine", help="PDF engine: weasyprint (default) or chromium."),
    out_dir: str = typer.Option("./reports", "--out", help="Output directory for reports."),
    yes: bool = typer.Option(False, "--yes", "-y", help="Skip the confirmation prompt."),
    fail_on: str = typer.Option(
        None,
        "--fail-on",
        help="Exit non-zero if any finding at/above this severity exists "
        "(critical|high|medium|low). Useful as a CI gate.",
    ),
    scanner_output: bool = typer.Option(
        False,
        "--scanner-output",
        help="Stream raw scanner stdout/stderr while commands run. Elapsed-time heartbeats are shown by default.",
    ),
):
    """Run the selected scanners and produce a consolidated report.

    Cross-account example:

        sentryhive scan --role-arn arn:aws:iam::1111:role/SecurityAudit \\
                        --role-arn arn:aws:iam::2222:role/SecurityAudit \\
                        --external-id shared-secret --client-name "Acme Corp" --pdf

    EKS hardening (separate opt-in phase, requires in-cluster access):

        sentryhive scan --role-arn ... --eks --clusters prod-eks --kubeconfig ~/.kube/client
    """
    selected = [s.strip() for s in scanners_opt.split(",") if s.strip()]
    unknown = [s for s in selected if s not in ALL_SCANNERS]
    if unknown:
        console.print(f"[red]Unknown scanner(s): {', '.join(unknown)}[/red]")
        raise typer.Exit(code=2)

    formats = _resolve_formats(output_formats, pdf)
    if pdf_engine not in ("weasyprint", "chromium"):
        console.print(f"[red]Unknown --pdf-engine '{pdf_engine}' (use weasyprint or chromium).[/red]")
        raise typer.Exit(code=2)

    region_list = [r.strip() for r in regions.split(",")] if regions else None
    cluster_list = [c.strip() for c in clusters.split(",")] if clusters else None
    logo_uri = _logo_data_uri(logo) if logo else ""
    generated_at = dt.datetime.now(dt.timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")

    aws_selected = [s for s in selected if s in ("prowler", "cloudsplaining")]
    ash_selected = "ash" in selected
    eks_requested = eks or "hardeneks" in selected
    needs_aws = bool(aws_selected) or eks_requested

    write_kwargs = {"formats": formats, "pdf_engine": pdf_engine, "console": console}
    reports = []

    if needs_aws:
        try:
            contexts = build_contexts(
                profile=profile,
                role_arns=role_arn or None,
                external_id=external_id,
                regions=region_list,
            )
        except AuthError as exc:
            console.print(f"[red]Authentication failed:[/red] {exc}")
            raise typer.Exit(code=1) from None

        _confirm(contexts, selected, eks_requested, client_name, yes)

        for ctx in contexts:
            console.rule(f"[bold]Account {ctx.identity.account_id}[/bold]")
            scanner_objs = build_scanners(aws_selected) + _eks_scanners(
                ctx,
                eks_requested,
                cluster_list,
                kubeconfig,
            )
            with tempfile.TemporaryDirectory(prefix="sentryhive-") as workdir:
                results = _run(scanner_objs, ctx, workdir, scanner_output=scanner_output)
                report = build_report(
                    results,
                    account_id=ctx.identity.account_id,
                    identity_arn=ctx.identity.arn,
                    regions=ctx.regions,
                    generated_at=generated_at,
                    client_name=client_name or "",
                    logo_data_uri=logo_uri,
                )
            target = out_dir if len(contexts) == 1 else os.path.join(out_dir, ctx.identity.account_id)
            paths = write_reports(report, target, **write_kwargs)
            _print_summary(report, paths)
            reports.append(report)

        if len(reports) > 1:
            console.rule("[bold]Roll-up across accounts[/bold]")
            rollup = build_rollup(
                reports, generated_at=generated_at, client_name=client_name or "", logo_data_uri=logo_uri
            )
            paths = write_reports(rollup, out_dir, **write_kwargs)
            _print_summary(rollup, paths)
            reports.append(rollup)

    if ash_selected:
        console.rule("[bold]Local IaC / code (ASH)[/bold]")
        ash = AshScanner(source_dir=source_dir)
        with tempfile.TemporaryDirectory(prefix="sentryhive-ash-") as workdir:
            results = _run([ash], None, workdir, scanner_output=scanner_output)
            ash_report = build_report(
                results,
                account_id="",
                identity_arn="",
                regions=[],
                generated_at=generated_at,
                client_name=client_name or "",
                logo_data_uri=logo_uri,
            )
        target = out_dir if not needs_aws else os.path.join(out_dir, "local-iac")
        paths = write_reports(ash_report, target, **write_kwargs)
        _print_summary(ash_report, paths)
        reports.append(ash_report)

    if not reports:
        console.print("[red]Nothing to scan.[/red]")
        raise typer.Exit(code=2)

    _maybe_fail_on(reports, fail_on)
    raise typer.Exit(code=0)


# --------------------------------------------------------------------------- #
# helpers
# --------------------------------------------------------------------------- #
def _resolve_formats(output_formats: str, pdf: bool) -> list[str]:
    formats = [f.strip().lower() for f in output_formats.split(",") if f.strip()]
    if pdf and "pdf" not in formats:
        formats.append("pdf")
    invalid = [f for f in formats if f not in VALID_FORMATS]
    if invalid:
        console.print(f"[red]Unknown format(s): {', '.join(invalid)}. Valid: {', '.join(sorted(VALID_FORMATS))}[/red]")
        raise typer.Exit(code=2)
    return formats


def _eks_scanners(ctx, eks_requested: bool, cluster_list, kubeconfig) -> list[Scanner]:
    """EKS hardening is opt-in. In the default run we only *detect and note* clusters;
    we never silently run hardeneks (it needs in-cluster RBAC access)."""
    detected = discover_eks_clusters(ctx)
    if not eks_requested:
        if detected:
            console.print(
                f"[yellow]Found {len(detected)} EKS cluster(s): {', '.join(detected)}.[/yellow]\n"
                "[dim]Run EKS hardening with --eks (requires in-cluster access — see docs/eks-access.md).[/dim]"
            )
        return []
    targets = cluster_list or detected
    if not targets:
        console.print("[yellow]--eks requested but no EKS clusters found in this account.[/yellow]")
        return []
    console.print(f"[dim]EKS hardening targets: {', '.join(targets)}[/dim]")
    return [HardeneksScanner(cluster=c, kubeconfig=kubeconfig) for c in targets]


def _run(scanner_objs: list[Scanner], ctx, workdir: str, scanner_output: bool = False):
    results = []
    for scanner in scanner_objs:
        scanner.show_scanner_output = scanner_output
        console.print(f"▶ running [bold]{scanner.name}[/bold] …")
        result = scanner.run(ctx, workdir)
        style = {"ok": "green", "skipped": "yellow", "error": "red"}[result.status.value]
        note = f" — {result.message}" if result.message else ""
        console.print(f"  [{style}]{result.status.value}[/{style}] ({len(result.findings)} findings){note}")
        results.append(result)
    return results


def _confirm(contexts, selected, eks_requested, client_name, yes):
    lines = []
    if client_name:
        lines.append(f"[bold]Client:[/bold] {client_name}")
    for ctx in contexts:
        lines.append(f"[bold]Account:[/bold] {ctx.identity.account_id}  [dim]{ctx.identity.arn}[/dim]")
    lines.append(f"[bold]Regions:[/bold] {', '.join(contexts[0].regions)}")
    eks_note = " + EKS hardening" if eks_requested else ""
    lines.append(f"[bold]Scanners:[/bold] {', '.join(selected)}{eks_note}")
    console.print(Panel.fit("\n".join(lines), title="About to scan", border_style="yellow"))
    if not yes and not typer.confirm("Proceed?", default=True):
        console.print("Aborted.")
        raise typer.Exit(code=0)


def _logo_data_uri(path: str) -> str:
    if not os.path.isfile(path):
        console.print(f"[yellow]Logo not found, ignoring: {path}[/yellow]")
        return ""
    mime = mimetypes.guess_type(path)[0] or "image/png"
    with open(path, "rb") as fh:
        encoded = base64.b64encode(fh.read()).decode()
    return f"data:{mime};base64,{encoded}"


def _maybe_fail_on(reports, fail_on):
    if not fail_on:
        return
    from sentryhive.models import Severity

    threshold = Severity.parse(fail_on)
    breaching = [f for r in reports for f in r.findings if f.status == "fail" and f.severity >= threshold]
    if breaching:
        console.print(
            f"[red]✗ {len(breaching)} finding(s) at or above {threshold.label} — failing per --fail-on.[/red]"
        )
        raise typer.Exit(code=3)


def _print_summary(report, paths: dict[str, str]):
    table = Table(title=f"Findings by severity{' — ' + report.account_id if report.account_id else ''}")
    table.add_column("Severity")
    table.add_column("Count", justify="right")
    for sev in ["Critical", "High", "Medium", "Low", "Info"]:
        table.add_row(sev, str(report.severity_counts.get(sev, 0)))
    table.add_row("[bold]Total[/bold]", f"[bold]{report.total}[/bold]")
    console.print(table)
    if report.compliance:
        ct = Table(title="Compliance posture")
        ct.add_column("Framework")
        ct.add_column("Pass", justify="right")
        ct.add_column("Fail", justify="right")
        ct.add_column("% pass", justify="right")
        for c in report.compliance:
            ct.add_row(c.framework, str(c.passed), str(c.failed), f"{c.pass_pct}%")
        console.print(ct)
    console.print("\n[bold]Reports written:[/bold]")
    for fmt, path in paths.items():
        console.print(f"  • {fmt}: [cyan]{path}[/cyan]")


if __name__ == "__main__":  # pragma: no cover
    sys.exit(app())
