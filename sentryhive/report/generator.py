"""Render an aggregated Report into report.html, report.md and findings.json."""

from __future__ import annotations

import json
import os

from jinja2 import Environment, PackageLoader, select_autoescape

from sentryhive.aggregate import Report

_SEVERITY_ORDER = ["Critical", "High", "Medium", "Low", "Info"]
_SEVERITY_COLORS = {
    "Critical": "#7f1d1d",
    "High": "#dc2626",
    "Medium": "#d97706",
    "Low": "#2563eb",
    "Info": "#6b7280",
}


def _env() -> Environment:
    env = Environment(
        loader=PackageLoader("sentryhive.report", "templates"),
        autoescape=select_autoescape(["html", "xml"]),
        trim_blocks=True,
        lstrip_blocks=True,
    )
    env.globals["severity_order"] = _SEVERITY_ORDER
    env.globals["severity_colors"] = _SEVERITY_COLORS
    return env


def write_reports(report: Report, out_dir: str) -> dict[str, str]:
    """Write all three artifacts; return a map of format -> path."""
    os.makedirs(out_dir, exist_ok=True)
    env = _env()

    paths: dict[str, str] = {}

    html_path = os.path.join(out_dir, "report.html")
    with open(html_path, "w") as fh:
        fh.write(env.get_template("report.html.j2").render(r=report))
    paths["html"] = html_path

    md_path = os.path.join(out_dir, "report.md")
    with open(md_path, "w") as fh:
        fh.write(env.get_template("report.md.j2").render(r=report))
    paths["md"] = md_path

    json_path = os.path.join(out_dir, "findings.json")
    with open(json_path, "w") as fh:
        json.dump(report.to_dict(), fh, indent=2)
    paths["json"] = json_path

    return paths
