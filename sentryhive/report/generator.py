"""Render an aggregated Report into report.html / report.md / findings.json / report.pdf.

PDF reuses the self-contained HTML as the single source of truth: WeasyPrint (default,
pure-Python, no browser) or headless Chromium (opt-in, pixel-perfect) renders it via
the template's `@media print` rules. PDF generation is fully local — no network calls.
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import tempfile

from jinja2 import Environment, PackageLoader, select_autoescape

from sentryhive.aggregate import Report

VALID_FORMATS = {"html", "md", "json", "pdf"}

_SEVERITY_ORDER = ["Critical", "High", "Medium", "Low", "Info"]
_SEVERITY_COLORS = {
    "Critical": "#7f1d1d",
    "High": "#dc2626",
    "Medium": "#d97706",
    "Low": "#2563eb",
    "Info": "#6b7280",
}


class PdfError(RuntimeError):
    """Raised when PDF rendering is requested but cannot be completed."""


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


def render_html(report: Report) -> str:
    return _env().get_template("report.html.j2").render(r=report)


def render_md(report: Report) -> str:
    return _env().get_template("report.md.j2").render(r=report)


def write_reports(
    report: Report,
    out_dir: str,
    *,
    formats: list[str] | tuple[str, ...] = ("html", "md", "json"),
    pdf_engine: str = "weasyprint",
    console=None,
) -> dict[str, str]:
    """Write the requested artifacts; return a map of format -> path.

    A PDF failure (missing engine/system libs) is reported but does not abort the
    other formats — the consultant still gets HTML/MD/JSON.
    """
    os.makedirs(out_dir, exist_ok=True)
    formats = list(formats)
    paths: dict[str, str] = {}

    # HTML is needed on disk if requested, and as the source for PDF.
    html = render_html(report) if ("html" in formats or "pdf" in formats) else None

    if "html" in formats:
        html_path = os.path.join(out_dir, "report.html")
        with open(html_path, "w") as fh:
            fh.write(html)
        paths["html"] = html_path

    if "md" in formats:
        md_path = os.path.join(out_dir, "report.md")
        with open(md_path, "w") as fh:
            fh.write(render_md(report))
        paths["md"] = md_path

    if "json" in formats:
        json_path = os.path.join(out_dir, "findings.json")
        with open(json_path, "w") as fh:
            json.dump(report.to_dict(), fh, indent=2)
        paths["json"] = json_path

    if "pdf" in formats:
        pdf_path = os.path.join(out_dir, "report.pdf")
        try:
            render_pdf(html, pdf_path, engine=pdf_engine)
            paths["pdf"] = pdf_path
        except PdfError as exc:
            msg = f"PDF generation skipped: {exc}"
            if console is not None:
                console.print(f"[yellow]{msg}[/yellow]")
            else:  # pragma: no cover
                print(msg)

    return paths


def render_pdf(html: str, pdf_path: str, *, engine: str = "weasyprint") -> None:
    if engine == "weasyprint":
        _render_weasyprint(html, pdf_path)
    elif engine == "chromium":
        _render_chromium(html, pdf_path)
    else:  # pragma: no cover - validated upstream
        raise PdfError(f"unknown PDF engine '{engine}'")


def _render_weasyprint(html: str, pdf_path: str) -> None:
    try:
        from weasyprint import HTML  # imported lazily; heavy + optional
    except Exception as exc:  # noqa: BLE001 - ImportError or missing system libs
        raise PdfError(
            "WeasyPrint is not available. Install it with `pip install sentryhive[pdf]` "
            f"(needs system libs pango/cairo), or use the Docker image. ({exc})"
        ) from exc
    HTML(string=html).write_pdf(pdf_path)


def _render_chromium(html: str, pdf_path: str) -> None:
    chrome = next(
        (c for c in ("chromium", "chromium-browser", "google-chrome", "google-chrome-stable") if shutil.which(c)), None
    )
    if not chrome:
        raise PdfError("no Chromium/Chrome binary found on PATH for --pdf-engine chromium")
    with tempfile.NamedTemporaryFile("w", suffix=".html", delete=False) as tmp:
        tmp.write(html)
        tmp_path = tmp.name
    try:
        proc = subprocess.run(
            [
                chrome,
                "--headless",
                "--no-sandbox",
                "--disable-gpu",
                f"--print-to-pdf={pdf_path}",
                "--no-pdf-header-footer",
                f"file://{tmp_path}",
            ],
            capture_output=True,
            text=True,
            timeout=120,
            check=False,
        )
        if not os.path.exists(pdf_path):
            raise PdfError(f"chromium failed to produce a PDF: {proc.stderr[-300:]}")
    finally:
        os.unlink(tmp_path)
