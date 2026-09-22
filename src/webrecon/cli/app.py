"""WebRecon CLI entry point (§30).

Phase 1 wires the foundation commands (version, db init, module listing). The
``scan`` command is filled in as the engine + pipeline land in later phases; it
is present now so the surface is stable and discoverable.
"""

from __future__ import annotations

import asyncio
import sys

import typer
from rich.console import Console
from rich.table import Table

from .. import __version__
from ..core.config import ScanConfig
from ..core.logging import configure_logging
from ..core.registry import default_registry
from ..storage import init_db

app = typer.Typer(
    name="webrecon",
    help="Local-first Website Intelligence & Security Assessment workstation. "
    "Use only on assets you own or are authorized to test.",
    no_args_is_help=True,
    add_completion=False,
)
console = Console()


@app.command()
def version() -> None:
    """Print the WebRecon version."""
    console.print(f"WebRecon [bold cyan]{__version__}[/]")


@app.command("init-db")
def init_db_cmd(
    database_url: str = typer.Option(
        "sqlite+aiosqlite:///webrecon.db", "--database-url", help="SQLAlchemy async URL."
    ),
) -> None:
    """Create the local scan database schema."""
    configure_logging()

    async def _run() -> None:
        db = await init_db(database_url)
        await db.dispose()

    asyncio.run(_run())
    console.print(f"[green]OK[/] database ready at [bold]{database_url}[/]")


@app.command()
def modules() -> None:
    """List registered scanner modules and their dependencies."""
    # Import side-effect: registers built-in modules as they are implemented.
    from .. import modules as _  # noqa: F401

    if not len(default_registry):
        console.print("[yellow]No modules registered yet.[/]")
        raise typer.Exit(0)

    table = Table(title="Registered scanner modules")
    table.add_column("name", style="cyan")
    table.add_column("version")
    table.add_column("requires", style="dim")
    table.add_column("description")
    for name in default_registry.resolution_order():
        cls = default_registry.get(name)
        table.add_row(name, cls.version, ", ".join(cls.requires) or "—", cls.description)
    console.print(table)


@app.command()
def scan(
    url: str = typer.Argument(..., help="Target URL you own or are authorized to test."),
    config_file: str | None = typer.Option(
        None, "--config", help="Load a base config from a TOML file (flags override it)."
    ),
    depth: int | None = typer.Option(None, "--depth", help="Max crawl depth (default 3)."),
    max_pages: int | None = typer.Option(None, "--max-pages", help="Max pages (default 300)."),
    modules_opt: str | None = typer.Option(
        None, "--modules", help="Comma-separated modules to run (default: all)."
    ),
    allow_private: bool | None = typer.Option(
        None, "--allow-private/--no-allow-private",
        help="Lab mode: permit private/loopback targets (§3).",
    ),
    rate: float | None = typer.Option(None, "--rate", help="Max requests/second."),
    concurrency: int | None = typer.Option(None, "--concurrency", help="Max concurrent requests."),
    timeout: float | None = typer.Option(None, "--timeout", help="Per-request timeout (seconds)."),
    no_robots: bool = typer.Option(
        False, "--no-robots", help="Ignore robots.txt (authorized only)."
    ),
    probe: bool = typer.Option(
        False, "--probe", help="Probe curated sensitive files (.git/.env/...); authorized only."
    ),
    active: bool = typer.Option(
        False, "--active", help="Active API/DB assessment (GET-only, detection); authorized only."
    ),
    browser: bool | None = typer.Option(
        None, "--browser/--no-browser", help="Use the headless browser engine."
    ),
    no_db: bool = typer.Option(False, "--no-db", help="Do not persist results to the database."),
    database_url: str = typer.Option(
        "sqlite+aiosqlite:///webrecon.db", "--database-url", help="SQLAlchemy async URL."
    ),
    json_out: str | None = typer.Option(None, "--json", help="Write JSON report to this path."),
    html_out: str | None = typer.Option(None, "--html", help="Write HTML report to this path."),
    pdf_out: str | None = typer.Option(None, "--pdf", help="Write PDF report to this path."),
) -> None:
    """Run a scan against a target you own or are authorized to test."""
    import json
    from pathlib import Path

    from .. import modules as _  # noqa: F401  register built-in modules
    from ..core.enums import ModuleStatus
    from ..core.registry import default_registry
    from ..pipeline import Pipeline, ScanProgress
    from ..reporting.html_report import render_html
    from ..reporting.json_report import build_report, collect_extras
    from ..storage import init_db

    configure_logging(json_output=False)

    if config_file:
        cfg = ScanConfig.from_toml(config_file)
    else:
        cfg = ScanConfig()
    # Flags override the config only when explicitly provided.
    if depth is not None:
        cfg.scope.max_depth = depth
    if max_pages is not None:
        cfg.scope.max_pages = max_pages
    if allow_private is not None:
        cfg.scope.allow_private_targets = allow_private
    if browser is not None:
        cfg.browser_mode = browser
    if rate is not None:
        cfg.rate.requests_per_second = rate
    if concurrency is not None:
        cfg.rate.concurrency = concurrency
    if timeout is not None:
        cfg.http.timeout_seconds = timeout
    if no_robots:
        cfg.crawl.respect_robots = False
    if probe:
        cfg.probe = True
    if active:
        cfg.active = True
    if modules_opt:
        cfg.enabled_modules = [m.strip() for m in modules_opt.split(",") if m.strip()]

    console.print(f"[bold]Scanning[/] {url}")
    if cfg.scope.allow_private_targets:
        console.print("[yellow]lab mode: private/loopback targets permitted[/]")
    if cfg.active or cfg.probe:
        console.print(
            "[red]Active checks enabled[/] — run only on assets you own or are "
            "explicitly authorized to test."
        )

    status_glyph = {
        ModuleStatus.SUCCESS: "[green]ok[/]",
        ModuleStatus.PARTIAL: "[yellow]partial[/]",
        ModuleStatus.FAILED: "[red]failed[/]",
        ModuleStatus.SKIPPED: "[dim]skipped[/]",
        ModuleStatus.TIMEOUT: "[red]timeout[/]",
        ModuleStatus.CANCELLED: "[yellow]cancelled[/]",
    }

    def on_progress(p: ScanProgress) -> None:
        glyph = status_glyph.get(p.status, str(p.status))
        console.print(f"  [{p.index + 1}/{p.total}] {p.module:<12} {glyph}")

    async def _run() -> tuple[dict, dict]:
        db = None if no_db else await init_db(database_url)
        try:
            pipeline = Pipeline(cfg, registry=default_registry, db=db, progress=on_progress)
            ctx = await pipeline.run(url)
            return build_report(ctx), collect_extras(ctx)
        finally:
            if db is not None:
                await db.dispose()

    report, extras = asyncio.run(_run())

    _print_summary(report)

    def _write(path: str, data: str | bytes) -> None:
        p = Path(path)
        p.parent.mkdir(parents=True, exist_ok=True)
        if isinstance(data, bytes):
            p.write_bytes(data)
        else:
            p.write_text(data, encoding="utf-8")

    if json_out:
        _write(json_out, json.dumps(report, indent=2))
        console.print(f"[green]OK[/] JSON report written to [bold]{json_out}[/]")
    if html_out or pdf_out:
        html = render_html(report, extras)
        if html_out:
            _write(html_out, html)
            console.print(f"[green]OK[/] HTML report written to [bold]{html_out}[/]")
        if pdf_out:
            from ..reporting.pdf_report import PdfUnavailableError, render_pdf

            try:
                _write(pdf_out, render_pdf(html))
                console.print(f"[green]OK[/] PDF report written to [bold]{pdf_out}[/]")
            except PdfUnavailableError as exc:
                console.print(f"[red]PDF unavailable:[/] {exc}")


def _print_summary(report: dict) -> None:
    """Render a scan summary + findings table."""
    from ..core.enums import SEVERITY_ORDER, Severity

    sev_style = {
        "critical": "bold red",
        "high": "red",
        "medium": "yellow",
        "low": "cyan",
        "informational": "dim",
    }
    summary = report["summary"]
    console.print()
    console.print(f"[bold]Scan {report['scan_id']}[/] — {summary['total_findings']} finding(s)")
    counts = summary["by_severity"]
    parts = [
        f"[{sev_style.get(s.value, 'white')}]{s.value}={counts.get(s.value, 0)}[/]"
        for s in sorted(Severity, key=lambda x: SEVERITY_ORDER[x], reverse=True)
    ]
    console.print("  " + "  ".join(parts))

    findings = report["findings"]
    if findings:
        table = Table(title="Findings")
        table.add_column("severity")
        table.add_column("conf")
        table.add_column("obs")
        table.add_column("check")
        table.add_column("name")
        for f in findings:
            style = sev_style.get(f["severity"], "white")
            table.add_row(
                f"[{style}]{f['severity']}[/]",
                f["confidence"],
                f["observation"],
                f["check_id"],
                f["name"],
            )
        console.print(table)


@app.command()
def scans(
    database_url: str = typer.Option(
        "sqlite+aiosqlite:///webrecon.db", "--database-url", help="SQLAlchemy async URL."
    ),
) -> None:
    """List stored scans."""
    from ..api import queries
    from ..storage import init_db

    async def _run() -> list[dict]:
        db = await init_db(database_url)
        try:
            return await queries.list_scans(db)
        finally:
            await db.dispose()

    rows = asyncio.run(_run())
    if not rows:
        console.print("[yellow]No scans stored.[/]")
        raise typer.Exit(0)
    table = Table(title="Scans")
    table.add_column("id", style="cyan")
    table.add_column("target")
    table.add_column("status")
    table.add_column("findings", justify="right")
    table.add_column("created")
    for r in rows:
        table.add_row(r["id"][:8], r["target"], r["status"], str(r["findings"]),
                      r["created_at"][:19])
    console.print(table)


@app.command()
def report(
    scan_id: str = typer.Argument(..., help="Scan id (full or 8-char prefix)."),
    json_out: str | None = typer.Option(None, "--json", help="Write JSON report."),
    html_out: str | None = typer.Option(None, "--html", help="Write HTML report."),
    pdf_out: str | None = typer.Option(None, "--pdf", help="Write PDF report."),
    database_url: str = typer.Option(
        "sqlite+aiosqlite:///webrecon.db", "--database-url", help="SQLAlchemy async URL."
    ),
) -> None:
    """Regenerate a report from a stored scan (no re-scan)."""
    import json
    from pathlib import Path

    from ..api import queries
    from ..reporting.db_report import build_report_from_db
    from ..reporting.html_report import render_html
    from ..storage import init_db

    async def _run() -> tuple[dict, dict] | None:
        db = await init_db(database_url)
        try:
            # Resolve an 8-char prefix to a full id.
            full = scan_id
            if len(scan_id) < 36:
                for s in await queries.list_scans(db):
                    if s["id"].startswith(scan_id):
                        full = s["id"]
                        break
            return await build_report_from_db(db, full)
        finally:
            await db.dispose()

    built = asyncio.run(_run())
    if built is None:
        console.print(f"[red]Scan not found:[/] {scan_id}")
        raise typer.Exit(1)
    rep, extras = built

    def _write(path: str, data: str | bytes) -> None:
        p = Path(path)
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_bytes(data) if isinstance(data, bytes) else p.write_text(data, encoding="utf-8")

    if not any([json_out, html_out, pdf_out]):
        console.print(f"Scan {rep['scan_id'][:8]} — risk [bold]{rep['risk']['level']}[/], "
                      f"{rep['summary']['total_findings']} finding(s). "
                      f"Use --json/--html/--pdf to export.")
        raise typer.Exit(0)
    if json_out:
        _write(json_out, json.dumps(rep, indent=2))
        console.print(f"[green]OK[/] JSON -> {json_out}")
    if html_out or pdf_out:
        html = render_html(rep, extras)
        if html_out:
            _write(html_out, html)
            console.print(f"[green]OK[/] HTML -> {html_out}")
        if pdf_out:
            from ..reporting.pdf_report import PdfUnavailableError, render_pdf

            try:
                _write(pdf_out, render_pdf(html))
                console.print(f"[green]OK[/] PDF -> {pdf_out}")
            except PdfUnavailableError as exc:
                console.print(f"[red]PDF unavailable:[/] {exc}")


@app.command()
def serve(
    host: str = typer.Option("127.0.0.1", "--host", help="Bind host."),
    port: int = typer.Option(8000, "--port", help="Bind port."),
    database_url: str = typer.Option(
        "sqlite+aiosqlite:///webrecon.db", "--database-url", help="SQLAlchemy async URL."
    ),
) -> None:
    """Launch the dashboard (FastAPI) at http://host:port."""
    try:
        import uvicorn

        from ..api.app import create_app
    except ImportError:
        console.print("[red]Dashboard deps missing.[/] Install with: pip install -e '.[api]'")
        raise typer.Exit(1) from None

    console.print(f"[bold]WebRecon dashboard[/] on [cyan]http://{host}:{port}[/]")
    uvicorn.run(create_app(database_url), host=host, port=port, log_level="info")


def _force_utf8_stdio() -> None:
    """Best-effort: make stdout/stderr UTF-8 so rich box-drawing and status
    glyphs never raise ``UnicodeEncodeError`` on legacy Windows consoles."""
    for stream in ("stdout", "stderr"):
        s = getattr(sys, stream, None)
        reconfigure = getattr(s, "reconfigure", None)
        if reconfigure is not None:
            try:
                reconfigure(encoding="utf-8", errors="replace")
            except (ValueError, OSError):  # pragma: no cover - defensive
                pass


def main() -> None:
    _force_utf8_stdio()
    app()


if __name__ == "__main__":
    main()
