"""SentryHive command-line interface."""

from __future__ import annotations

import datetime as dt
import sys
import tempfile

import typer
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from sentryhive import __version__
from sentryhive.aggregate import build_report
from sentryhive.auth import AuthError, build_context
from sentryhive.report import write_reports
from sentryhive.scanners import ALL_SCANNERS, build_scanners
from sentryhive.scanners.base import ScanStatus

app = typer.Typer(
    add_completion=False,
    help="Point SentryHive at an AWS account and get one consolidated security report.",
)
console = Console()


def _version_callback(value: bool):
    if value:
        console.print(f"SentryHive {__version__}")
        raise typer.Exit()


@app.callback()
def main(
    _version: bool = typer.Option(
        False, "--version", callback=_version_callback, is_eager=True,
        help="Show version and exit.",
    ),
):
    """SentryHive — AWS security scanning toolkit."""


@app.command()
def scanners():
    """List available scanners."""
    table = Table(title="Available scanners")
    table.add_column("Name")
    table.add_column("Target")
    table.add_row("prowler", "live AWS account — config & compliance")
    table.add_row("cloudsplaining", "live AWS account — IAM policy risk")
    table.add_row("hardeneks", "live AWS account — EKS best practices")
    table.add_row("ash", "local code/IaC on disk")
    console.print(table)


@app.command()
def scan(
    profile: str = typer.Option(None, "--profile", help="AWS profile name."),
    role_arn: str = typer.Option(None, "--role-arn", help="IAM role ARN to assume (STS)."),
    external_id: str = typer.Option(None, "--external-id", help="External ID for role assumption."),
    regions: str = typer.Option(None, "--regions", help="Comma-separated regions (e.g. eu-central-1,us-east-1)."),
    scanners_opt: str = typer.Option(
        ",".join(ALL_SCANNERS), "--scanners",
        help=f"Comma-separated scanners to run. Available: {', '.join(ALL_SCANNERS)}.",
    ),
    eks_cluster: str = typer.Option(None, "--eks-cluster", help="EKS cluster name for hardeneks."),
    source_dir: str = typer.Option(None, "--source-dir", help="Directory ASH scans (defaults to CWD)."),
    out_dir: str = typer.Option("./reports", "--out", help="Output directory for reports."),
    yes: bool = typer.Option(False, "--yes", "-y", help="Skip the confirmation prompt."),
    fail_on: str = typer.Option(
        None, "--fail-on",
        help="Exit non-zero if any finding at/above this severity exists "
             "(critical|high|medium|low). Useful as a CI gate.",
    ),
):
    """Run the selected scanners and produce a consolidated report."""
    selected = [s.strip() for s in scanners_opt.split(",") if s.strip()]
    unknown = [s for s in selected if s not in ALL_SCANNERS]
    if unknown:
        console.print(f"[red]Unknown scanner(s): {', '.join(unknown)}[/red]")
        raise typer.Exit(code=2)

    region_list = [r.strip() for r in regions.split(",")] if regions else None

    # Does any selected scanner need live AWS auth?
    scanner_objs = build_scanners(selected, eks_cluster=eks_cluster, source_dir=source_dir)
    needs_aws = any(s.requires_aws for s in scanner_objs)

    ctx = None
    if needs_aws:
        try:
            ctx = build_context(
                profile=profile, role_arn=role_arn,
                external_id=external_id, regions=region_list,
            )
        except AuthError as exc:
            console.print(f"[red]Authentication failed:[/red] {exc}")
            raise typer.Exit(code=1) from None

        console.print(
            Panel.fit(
                f"[bold]Account:[/bold] {ctx.identity.account_id}\n"
                f"[bold]Identity:[/bold] {ctx.identity.arn}\n"
                f"[bold]Regions:[/bold] {', '.join(ctx.regions)}\n"
                f"[bold]Scanners:[/bold] {', '.join(selected)}",
                title="About to scan", border_style="yellow",
            )
        )
        if not yes and not typer.confirm("Proceed?", default=True):
            console.print("Aborted.")
            raise typer.Exit(code=0)
    else:
        console.print(f"[dim]No live-AWS scanners selected; running: {', '.join(selected)}[/dim]")

    results = []
    with tempfile.TemporaryDirectory(prefix="sentryhive-") as workdir:
        for scanner in scanner_objs:
            console.print(f"▶ running [bold]{scanner.name}[/bold] …")
            result = scanner.run(ctx, workdir)
            style = {"ok": "green", "skipped": "yellow", "error": "red"}[result.status.value]
            note = f" — {result.message}" if result.message else ""
            console.print(
                f"  [{style}]{result.status.value}[/{style}] "
                f"({len(result.findings)} findings){note}"
            )
            results.append(result)

        report = build_report(
            results,
            account_id=ctx.identity.account_id if ctx else "",
            identity_arn=ctx.identity.arn if ctx else "",
            regions=ctx.regions if ctx else (region_list or []),
            generated_at=dt.datetime.now(dt.timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC"),
        )
        paths = write_reports(report, out_dir)

    _print_summary(report, paths)

    if all(r.status == ScanStatus.ERROR for r in results) and results:
        raise typer.Exit(code=1)

    if fail_on:
        from sentryhive.models import Severity
        threshold = Severity.parse(fail_on)
        breaching = [f for f in report.findings if f.status == "fail" and f.severity >= threshold]
        if breaching:
            console.print(
                f"[red]✗ {len(breaching)} finding(s) at or above {threshold.label} "
                f"— failing per --fail-on.[/red]"
            )
            raise typer.Exit(code=3)

    raise typer.Exit(code=0)


def _print_summary(report, paths: dict[str, str]):
    table = Table(title="Findings by severity")
    table.add_column("Severity")
    table.add_column("Count", justify="right")
    for sev in ["Critical", "High", "Medium", "Low", "Info"]:
        table.add_row(sev, str(report.severity_counts.get(sev, 0)))
    table.add_row("[bold]Total[/bold]", f"[bold]{report.total}[/bold]")
    console.print(table)
    console.print("\n[bold]Reports written:[/bold]")
    for fmt, path in paths.items():
        console.print(f"  • {fmt}: [cyan]{path}[/cyan]")


if __name__ == "__main__":  # pragma: no cover
    sys.exit(app())
