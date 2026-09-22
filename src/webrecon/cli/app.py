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
    depth: int = typer.Option(3, "--depth", help="Max crawl depth."),
    max_pages: int = typer.Option(300, "--max-pages", help="Max pages to crawl."),
    modules_opt: str | None = typer.Option(
        None, "--modules", help="Comma-separated modules to run (default: all)."
    ),
    allow_private: bool = typer.Option(
        False, "--allow-private", help="Lab mode: permit private/loopback targets (§3)."
    ),
    browser: bool = typer.Option(False, "--browser", help="Use the headless browser engine."),
    no_db: bool = typer.Option(False, "--no-db", help="Do not persist results to the database."),
    database_url: str = typer.Option(
        "sqlite+aiosqlite:///webrecon.db", "--database-url", help="SQLAlchemy async URL."
    ),
    json_out: str | None = typer.Option(None, "--json", help="Write JSON report to this path."),
) -> None:
    """Run a scan against a target you own or are authorized to test."""
    import json
    from pathlib import Path

    from .. import modules as _  # noqa: F401  register built-in modules
    from ..core.enums import ModuleStatus
    from ..core.registry import default_registry
    from ..pipeline import Pipeline, ScanProgress
    from ..reporting.json_report import build_report
    from ..storage import init_db

    configure_logging(json_output=False)

    cfg = ScanConfig()
    cfg.scope.max_depth = depth
    cfg.scope.max_pages = max_pages
    cfg.scope.allow_private_targets = allow_private
    cfg.browser_mode = browser
    if modules_opt:
        cfg.enabled_modules = [m.strip() for m in modules_opt.split(",") if m.strip()]

    console.print(f"[bold]Scanning[/] {url}")
    if allow_private:
        console.print("[yellow]lab mode: private/loopback targets permitted[/]")

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

    async def _run() -> dict:
        db = None if no_db else await init_db(database_url)
        try:
            pipeline = Pipeline(cfg, registry=default_registry, db=db, progress=on_progress)
            ctx = await pipeline.run(url)
            return build_report(ctx)
        finally:
            if db is not None:
                await db.dispose()

    report = asyncio.run(_run())

    _print_summary(report)

    if json_out:
        Path(json_out).parent.mkdir(parents=True, exist_ok=True)
        Path(json_out).write_text(json.dumps(report, indent=2), encoding="utf-8")
        console.print(f"[green]OK[/] JSON report written to [bold]{json_out}[/]")


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
