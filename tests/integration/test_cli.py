"""CLI commands via Typer's runner (§30)."""

from __future__ import annotations

import asyncio

from typer.testing import CliRunner

from webrecon.cli.app import app
from webrecon.core.config import ScanConfig, ScopeMode
from webrecon.pipeline import Pipeline
from webrecon.storage.database import Database

runner = CliRunner()


def _db_url(tmp_path) -> str:
    return "sqlite+aiosqlite:///" + str(tmp_path / "cli.db").replace("\\", "/")


def _populate(url: str, mock_site: str) -> str:
    async def _run() -> str:
        cfg = ScanConfig()
        cfg.scope.allow_private_targets = True
        cfg.scope.mode = ScopeMode.SAME_ORIGIN
        cfg.rate.requests_per_second = 100
        cfg.http.verify_tls = False
        db = Database(url)
        await db.create_all()
        ctx = await Pipeline(cfg, db=db).run(mock_site)
        await db.dispose()
        return ctx.scan_id

    return asyncio.run(_run())


def test_version_and_modules() -> None:
    r = runner.invoke(app, ["version"])
    assert r.exit_code == 0 and "WebRecon" in r.stdout
    r = runner.invoke(app, ["modules"])
    assert r.exit_code == 0
    assert "target" in r.stdout and "security" in r.stdout


def test_scans_and_report(mock_site: str, tmp_path) -> None:
    url = _db_url(tmp_path)
    scan_id = _populate(url, mock_site)

    r = runner.invoke(app, ["scans", "--database-url", url])
    assert r.exit_code == 0
    assert scan_id[:8] in r.stdout

    # report summary (no export)
    r = runner.invoke(app, ["report", scan_id[:8], "--database-url", url])
    assert r.exit_code == 0
    assert "risk" in r.stdout.lower()

    # export HTML
    html_path = tmp_path / "r.html"
    r = runner.invoke(
        app, ["report", scan_id, "--database-url", url, "--html", str(html_path)]
    )
    assert r.exit_code == 0
    assert html_path.exists()
    assert "Executive Summary" in html_path.read_text(encoding="utf-8")


def test_scan_with_config_file(mock_site: str, tmp_path) -> None:
    cfg = tmp_path / "w.toml"
    cfg.write_text(
        '[scope]\nmode = "same-origin"\nallow_private_targets = true\nmax_pages = 5\n'
        "[rate]\nrequests_per_second = 100\n[http]\nverify_tls = false\n",
        encoding="utf-8",
    )
    r = runner.invoke(
        app, ["scan", mock_site, "--config", str(cfg), "--no-db", "--modules", "target,scope,http"]
    )
    assert r.exit_code == 0, r.stdout
    # Config loaded (allow_private_targets=true → lab mode) and the scan ran.
    assert "lab mode" in r.stdout
    assert "finding(s)" in r.stdout


def test_scan_active_prints_authorized_banner(mock_site: str) -> None:
    r = runner.invoke(
        app, ["scan", mock_site, "--allow-private", "--active", "--no-db",
              "--modules", "target,scope,http,crawler,api,apitest"]
    )
    assert r.exit_code == 0, r.stdout
    assert "Active checks enabled" in r.stdout
    assert "authorized" in r.stdout.lower()


def test_report_unknown_scan(tmp_path) -> None:
    url = _db_url(tmp_path)
    # empty db
    asyncio.run(_init_empty(url))
    r = runner.invoke(app, ["report", "nope", "--database-url", url])
    assert r.exit_code == 1


async def _init_empty(url: str) -> None:
    db = Database(url)
    await db.create_all()
    await db.dispose()
