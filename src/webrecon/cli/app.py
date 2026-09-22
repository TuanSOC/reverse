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
    browser: bool = typer.Option(False, "--browser", help="Use the headless browser engine."),
    json_out: str | None = typer.Option(None, "--json", help="Write JSON report to this path."),
) -> None:
    """Run a scan against a target (pipeline lands in the vertical-MVP phase)."""
    cfg = ScanConfig()
    cfg.scope.max_depth = depth
    cfg.scope.max_pages = max_pages
    cfg.browser_mode = browser
    console.print(
        f"[yellow]scan pipeline not yet wired[/] — target={url} "
        f"(depth={depth}, max_pages={max_pages}, browser={browser}, json={json_out})"
    )
    raise typer.Exit(code=0)


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
