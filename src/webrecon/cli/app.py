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
    login_url: str | None = typer.Option(
        None, "--login-url",
        help="Auto-login: URL of the login page. With --login-user/--login-pass, a "
             "headless browser logs in and reuses the session (authorized only).",
    ),
    login_user: str | None = typer.Option(None, "--login-user", help="Auto-login username."),
    login_pass: str | None = typer.Option(None, "--login-pass", help="Auto-login password."),
    cookie: str | None = typer.Option(
        None, "--cookie",
        help="Authenticated scan: raw Cookie header ('k=v; k2=v2'). Sent only to "
             "the target host. Authorized targets only.",
    ),
    header: list[str] | None = typer.Option(
        None, "--header", "-H",
        help="Extra request header 'Name: value' (repeatable), e.g. an "
             "Authorization token. Sent only to the target host.",
    ),
    no_db: bool = typer.Option(False, "--no-db", help="Do not persist results to the database."),
    database_url: str = typer.Option(
        "sqlite+aiosqlite:///webrecon.db", "--database-url", help="SQLAlchemy async URL."
    ),
    ai: bool = typer.Option(
        False, "--ai", help="After the scan, run the AI analysis (Groq if GROQ_API_KEY is "
                            "set, else the offline stub). Sends scan evidence to the provider."
    ),
    ai_provider: str | None = typer.Option(
        None, "--ai-provider", help="Force the AI provider: groq | stub."
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
    if login_url:
        cfg.auth.login_url = login_url
        cfg.auth.username = login_user
        cfg.auth.password = login_pass
    if cookie:
        cfg.http.cookie = cookie
    if header:
        for h in header:
            name, sep, value = h.partition(":")
            if sep and name.strip():
                cfg.http.auth_headers[name.strip()] = value.strip()
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
    if cfg.auth.enabled:
        console.print(
            "[yellow]auto-login:[/] a headless browser will log in at "
            f"{cfg.auth.login_url} and reuse the session (target host only). "
            "Authorized targets only."
        )
    if cfg.http.cookie or cfg.http.auth_headers:
        console.print(
            "[yellow]authenticated scan:[/] credentials will be sent to the "
            f"target host only ({url})."
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

    if ai and no_db:
        console.print("[yellow]--ai needs the database; skipping AI analysis (--no-db).[/]")
    if ai and not no_db:  # fail fast on a bad provider/missing key, before scanning
        from ..intel.ai import AiError, get_analyzer

        try:
            get_analyzer(ai_provider)
        except AiError as exc:
            console.print(f"[red]AI analysis unavailable:[/] {exc}")
            raise typer.Exit(2) from None

    async def _run() -> tuple[dict, dict, dict | None]:
        db = None if no_db else await init_db(database_url)
        try:
            pipeline = Pipeline(cfg, registry=default_registry, db=db, progress=on_progress)
            ctx = await pipeline.run(url)
            analysis = None
            if ai and db is not None:
                analysis = await _ai_best_effort(db, ctx.scan_id, ai_provider)
            exporting = bool(json_out or html_out or pdf_out)
            return build_report(ctx, include_intel=exporting), collect_extras(ctx), analysis
        finally:
            if db is not None:
                await db.dispose()

    report, extras, analysis = asyncio.run(_run())

    _print_summary(report)
    if analysis is not None:
        _print_ai(analysis)

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


async def _ai_best_effort(db, scan_id: str, provider: str | None) -> dict | None:
    """Run the AI analysis; report a provider error instead of failing the scan."""
    from ..intel.ai import AiError, analyze_scan

    try:
        return await analyze_scan(db, scan_id, provider=provider)
    except AiError as exc:
        console.print(f"[red]AI analysis failed:[/] {exc}")
        return None


_AI_TITLES = {
    "components": "Components", "attack_surface": "Attack surface",
    "auth_apis": "Authentication APIs", "static_vs_observed": "Static vs observed",
    "gaps": "Coverage gaps",
}


def _print_ai(analysis: dict) -> None:
    """Render an AI analysis; every claim shows its evidence IDs."""
    from rich.markup import escape

    console.print()
    console.print(f"[bold]AI analysis[/] [dim]({analysis['provider']} · {analysis['model']})[/]")
    summary = analysis.get("app_summary")
    if summary:
        console.print(f"  {escape(summary['text'])} [cyan]{', '.join(summary['evidence'])}[/]")
    for key, title in _AI_TITLES.items():
        claims = analysis["sections"].get(key) or []
        if not claims:
            continue
        console.print()
        console.print(f"[bold]{title}[/]")
        for c in claims:
            console.print(f"  • {escape(c['text'])} [cyan]{', '.join(c['evidence'])}[/]")
    if analysis.get("rejected_claims"):
        console.print()
        console.print(f"[dim]{analysis['rejected_claims']} claim(s) dropped: no valid "
                      "evidence ID.[/]")


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

    from ..reporting.db_report import build_report_from_db
    from ..reporting.html_report import render_html
    from ..storage import init_db

    async def _run() -> tuple[dict, dict] | None:
        db = await init_db(database_url)
        try:
            full = await _resolve_scan_id(db, scan_id) or scan_id
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


@app.command("ai")
def ai_cmd(
    scan_id: str = typer.Argument(..., help="Scan id (full or 8-char prefix)."),
    provider: str | None = typer.Option(None, "--provider", help="groq | stub (default: auto)."),
    show: bool = typer.Option(False, "--show", help="Show the latest stored analysis only."),
    json_out: str | None = typer.Option(None, "--json", help="Also write the analysis as JSON."),
    database_url: str = typer.Option(
        "sqlite+aiosqlite:///webrecon.db", "--database-url", help="SQLAlchemy async URL."
    ),
) -> None:
    """AI analysis of a stored scan (evidence-cited; Groq if GROQ_API_KEY is set)."""
    import json
    from pathlib import Path

    from ..intel.ai import AiError, analyze_scan, latest_analysis

    configure_logging()

    async def _run() -> dict | None:
        db = await init_db(database_url)
        try:
            full = await _resolve_scan_id(db, scan_id) or scan_id
            if show:
                return await latest_analysis(db, full)
            return await analyze_scan(db, full, provider=provider)
        finally:
            await db.dispose()

    try:
        result = asyncio.run(_run())
    except AiError as exc:
        console.print(f"[red]AI analysis failed:[/] {exc}")
        raise typer.Exit(1) from None
    if result is None:
        console.print(f"[red]No scan (or no stored analysis) for:[/] {scan_id}")
        raise typer.Exit(1)
    _print_ai(result)
    if json_out:
        out = Path(json_out)
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_text(json.dumps(result, indent=2), encoding="utf-8")
        console.print(f"[green]OK[/] JSON -> {json_out}")


# ---------------------------------------------------------------------------
# Read commands over stored scans (findings / endpoints / assets / graph)
# ---------------------------------------------------------------------------

_DB_OPT = typer.Option("sqlite+aiosqlite:///webrecon.db", "--database-url",
                       help="SQLAlchemy async URL.")
_SCAN_ARG = typer.Argument(None, help="Scan id or 8-char prefix (default: the latest scan).")
_JSON_OPT = typer.Option(False, "--json", help="Print raw JSON instead of a table (for scripts).")
async def _resolve_scan_id(db, scan_id: str | None) -> str | None:
    """Full id for ``scan_id`` (exact or unique prefix); the newest scan when ``None``.

    An ambiguous prefix is an error (exit 2) rather than silently picking one.
    """
    from sqlalchemy import select

    from ..storage.models import Scan

    async with db.session() as s:
        if not scan_id:
            return await s.scalar(select(Scan.id).order_by(Scan.created_at.desc()).limit(1))
        if await s.get(Scan, scan_id) is not None:
            return scan_id
        matches = (await s.execute(
            select(Scan.id).where(Scan.id.startswith(scan_id, autoescape=True))
            .order_by(Scan.created_at.desc()).limit(6)
        )).scalars().all()
    if len(matches) > 1:
        console.print(f"[red]Ambiguous scan id prefix[/] {scan_id!r} matches "
                      f"{', '.join(m[:8] for m in matches)} — use more characters.")
        raise typer.Exit(2)
    return matches[0] if matches else None


def _load_for_scan(database_url: str, scan_id: str | None, fetch):
    """Open the DB, resolve the scan, run ``fetch(db, sid)``; exit 1 if no scan."""

    async def _run():
        db = await init_db(database_url)
        try:
            sid = await _resolve_scan_id(db, scan_id)
            if sid is None:
                return None, None
            return sid, await fetch(db, sid)
        finally:
            await db.dispose()

    sid, data = asyncio.run(_run())
    if sid is None:
        msg = f"Scan not found: {scan_id}" if scan_id else "No scans stored yet."
        console.print(f"[red]{msg}[/]")
        raise typer.Exit(1)
    return sid, data


def _emit_json(data) -> None:
    import json

    typer.echo(json.dumps(data, indent=2, default=str))


@app.command("findings")
def findings_cmd(
    scan_id: str | None = _SCAN_ARG,
    min_severity: str | None = typer.Option(
        None, "--min-severity", help="Only show findings at/above this severity."),
    as_json: bool = _JSON_OPT,
    database_url: str = _DB_OPT,
) -> None:
    """List the findings of a stored scan (most severe first)."""
    from rich.markup import escape

    from ..api import queries
    from ..core.enums import SEVERITY_ORDER

    rank = {str(k): v for k, v in SEVERITY_ORDER.items()}
    floor = rank.get((min_severity or "").lower(), -1)
    if min_severity and floor < 0:
        console.print(f"[red]Unknown severity:[/] {min_severity}")
        raise typer.Exit(2)
    sid, rows = _load_for_scan(database_url, scan_id, queries.get_findings)
    rows = [f for f in rows if rank.get(f["severity"], 0) >= floor]
    if as_json:
        _emit_json(rows)
        return
    table = Table(title=f"Findings · scan {sid[:8]} ({len(rows)})")
    for col in ("severity", "conf", "obs", "check", "name"):
        table.add_column(col)
    for f in rows:
        table.add_row(f["severity"], f["confidence"], f["observation"],
                      escape(f["check_id"]), escape(f["name"]))
    console.print(table)


@app.command("endpoints")
def endpoints_cmd(
    scan_id: str | None = _SCAN_ARG,
    observation: str | None = typer.Option(
        None, "--observation", help="Filter: observed | referenced | potential."),
    as_json: bool = _JSON_OPT,
    database_url: str = _DB_OPT,
) -> None:
    """List API endpoints of a stored scan with discovery status and parameters."""
    from rich.markup import escape

    from ..api import queries

    sid, rows = _load_for_scan(database_url, scan_id, queries.get_endpoints)
    if observation:
        rows = [e for e in rows if e["observation"] == observation.lower()]
    from ..reporting.intel_sections import OBSERVATION_RANK

    rows.sort(key=lambda e: (OBSERVATION_RANK.get(e["observation"], 3), e["url"]))
    if as_json:
        _emit_json(rows)
        return
    table = Table(title=f"Endpoints · scan {sid[:8]} ({len(rows)})")
    for col in ("obs", "method", "url", "discovery", "params"):
        table.add_column(col)
    for e in rows:
        meta = e.get("meta") or {}
        params = ", ".join(f"{p.get('name')}:{p.get('classification')}"
                           for p in meta.get("params") or [])
        table.add_row(e["observation"], e.get("method") or "—", escape(e["url"]),
                      (meta.get("discovery_status") or "—").replace("_", " ").lower(),
                      escape(params) or "—")
    console.print(table)


@app.command("assets")
def assets_cmd(
    scan_id: str | None = _SCAN_ARG,
    asset_type: str | None = typer.Option(
        None, "--type", help="Filter by asset type, e.g. script, stylesheet, image."),
    as_json: bool = _JSON_OPT,
    database_url: str = _DB_OPT,
) -> None:
    """List discovered static assets of a stored scan."""
    from rich.markup import escape

    from ..api import queries

    sid, rows = _load_for_scan(database_url, scan_id, queries.get_assets)
    if asset_type:
        rows = [a for a in rows if a["asset_type"] == asset_type.lower()]
    rows.sort(key=lambda a: (a["asset_type"], a["url"]))
    if as_json:
        _emit_json(rows)
        return
    table = Table(title=f"Assets · scan {sid[:8]} ({len(rows)})")
    for col in ("type", "obs", "size", "url"):
        table.add_column(col)
    for a in rows:
        size = f"{a['size_bytes']:,} B" if a.get("size_bytes") else "—"
        table.add_row(a["asset_type"], a["observation"], size, escape(a["url"]))
    console.print(table)


@app.command("graph")
def graph_cmd(
    scan_id: str | None = _SCAN_ARG,
    as_json: bool = _JSON_OPT,
    database_url: str = _DB_OPT,
) -> None:
    """Summarize the unified asset graph of a stored scan (``--json`` for nodes/edges)."""
    from collections import Counter

    from ..api import queries

    sid, graph = _load_for_scan(database_url, scan_id, queries.get_graph)
    if as_json:
        _emit_json(graph)
        return
    nodes = Counter(n["type"] for n in graph["nodes"])
    edges = Counter(e["relation"] for e in graph["edges"])
    console.print(f"[bold]Asset graph · scan {sid[:8]}[/] — {len(graph['nodes'])} node(s), "
                  f"{len(graph['edges'])} edge(s)")
    nt = Table(title="Nodes by type")
    nt.add_column("type")
    nt.add_column("count", justify="right")
    for k, v in nodes.most_common():
        nt.add_row(k, str(v))
    et = Table(title="Edges by relation")
    et.add_column("relation")
    et.add_column("count", justify="right")
    for k, v in edges.most_common():
        et.add_row(k, str(v))
    console.print(nt)
    console.print(et)


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
