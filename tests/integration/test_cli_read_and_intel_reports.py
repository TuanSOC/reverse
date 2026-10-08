"""Integration: CLI read commands + intelligence sections in HTML/JSON/PDF reports."""

from __future__ import annotations

import asyncio
import json

import pytest
from typer.testing import CliRunner

from webrecon.cli.app import app as cli
from webrecon.core.config import ScanConfig, ScopeMode
from webrecon.pipeline import Pipeline
from webrecon.reporting.db_report import build_report_from_db
from webrecon.reporting.html_report import render_html
from webrecon.reporting.json_report import build_report, collect_extras
from webrecon.storage.database import Database

SECTIONS = ("Attack Surface", "API Endpoints", "Parameters", "Authentication Flow")


def _cfg() -> ScanConfig:
    c = ScanConfig()
    c.scope.allow_private_targets = True
    c.scope.mode = ScopeMode.SAME_ORIGIN
    c.rate.requests_per_second = 100
    c.http.verify_tls = False
    return c


def _db_url(tmp_path) -> str:
    return "sqlite+aiosqlite:///" + str(tmp_path / "r.db").replace("\\", "/")


@pytest.fixture
def stored_scan(mock_site: str, tmp_path):
    """Two scans of the mock site; returns (db_url, older_id, newest_id)."""
    url = _db_url(tmp_path)

    async def _run():
        db = Database(url)
        await db.create_all()
        first = await Pipeline(_cfg(), db=db).run(mock_site)
        second = await Pipeline(_cfg(), db=db).run(mock_site)
        await db.dispose()
        return first.scan_id, second.scan_id

    old, new = asyncio.run(_run())
    return url, old, new


def _run(*args: str):
    return CliRunner().invoke(cli, list(args))


_run_cli = _run


# -- CLI read commands ------------------------------------------------------------


def test_read_commands_default_to_latest_scan(stored_scan) -> None:
    url, old, new = stored_scan
    for cmd in ("findings", "endpoints", "assets", "graph"):
        res = _run(cmd, "--database-url", url)
        assert res.exit_code == 0, (cmd, res.output)
        assert new[:8] in res.output and old[:8] not in res.output, cmd


def test_read_commands_accept_prefix_and_json(stored_scan) -> None:
    url, old, _ = stored_scan
    findings = json.loads(_run("findings", old[:8], "--json", "--database-url", url).output)
    assert findings and all("check_id" in f for f in findings)
    endpoints = json.loads(_run("endpoints", old, "--json", "--database-url", url).output)
    assert any(e["observation"] == "observed" for e in endpoints)
    assets = json.loads(_run("assets", old[:8], "--json", "--database-url", url).output)
    assert any(a["asset_type"] == "script" for a in assets)
    graph = json.loads(_run("graph", old[:8], "--json", "--database-url", url).output)
    assert graph["nodes"] and graph["edges"]
    # secrets never surface through the read commands
    assert "AKIAIOSFODNN7EXAMPLE" not in json.dumps([findings, endpoints, assets, graph])


def test_read_command_filters(stored_scan) -> None:
    url, _, _ = stored_scan
    hi = json.loads(_run("findings", "--min-severity", "high", "--json",
                         "--database-url", url).output)
    assert all(f["severity"] in ("high", "critical") for f in hi)
    obs = json.loads(_run("endpoints", "--observation", "observed", "--json",
                          "--database-url", url).output)
    assert obs and all(e["observation"] == "observed" for e in obs)
    scripts = json.loads(_run("assets", "--type", "script", "--json",
                              "--database-url", url).output)
    assert scripts and all(a["asset_type"] == "script" for a in scripts)
    assert _run("findings", "--min-severity", "bogus", "--database-url", url).exit_code == 2


def test_scan_id_prefix_must_be_unambiguous(mock_site: str, tmp_path) -> None:
    url = _db_url(tmp_path)

    async def _run():
        db = Database(url)
        await db.create_all()
        for sid in ("abcd0001-0000-0000-0000-000000000000", "abcd0002-0000-0000-0000-000000000000"):
            await Pipeline(_cfg(), db=db).run(mock_site, scan_id=sid)
        await db.dispose()

    asyncio.run(_run())
    res = _run_cli("findings", "abcd", "--database-url", url)
    assert res.exit_code == 2 and "Ambiguous" in res.output
    res = _run_cli("findings", "abcd0001", "--database-url", url)
    assert res.exit_code == 0 and "abcd0001" in res.output
    # LIKE wildcards in the prefix are literal, never "match anything"
    assert _run_cli("findings", "%", "--database-url", url).exit_code == 1
    assert _run_cli("report", "_bcd", "--database-url", url).exit_code == 1


def test_read_commands_unknown_or_empty(tmp_path, stored_scan) -> None:
    url, _, _ = stored_scan
    res = _run("findings", "zzzzzzzz", "--database-url", url)
    assert res.exit_code == 1 and "Scan not found" in res.output
    empty = "sqlite+aiosqlite:///" + str(tmp_path / "empty.db").replace("\\", "/")
    res = _run("graph", "--database-url", empty)
    assert res.exit_code == 1 and "No scans stored" in res.output


# -- intelligence sections in reports -------------------------------------------------


def _check_intel(intel: dict) -> None:
    assert intel["attack_surface"]["type"] == "domain"
    assert intel["attack_surface"]["finding_count"] > 0
    assert intel["endpoints"] and intel["summary"]["observed"] > 0
    names = {p["name"] for p in intel["parameters"]}
    assert {"id", "q"} & names  # /api/item?id=1, /api/search?q=1 on the mock site
    assert any(p["sensitive"] for p in intel["parameters"])  # id → object identifier
    assert "kind" in intel["auth_flow"] and "endpoints" in intel["auth_flow"]


def test_reports_from_db_include_intel(stored_scan) -> None:
    url, old, _ = stored_scan

    async def _build():
        db = Database(url)
        try:
            return await build_report_from_db(db, old)
        finally:
            await db.dispose()

    rep, extras = asyncio.run(_build())
    _check_intel(rep["intelligence"])
    html = render_html(rep, extras)
    for title in SECTIONS:
        assert title in html
    assert "AKIAIOSFODNN7EXAMPLE" not in html + json.dumps(rep)

    # CLI exports carry the same sections
    tmp = __import__("pathlib").Path(url.split(":///", 1)[1]).parent
    out_json, out_html = tmp / "r.json", tmp / "r.html"
    res = _run("report", old[:8], "--database-url", url, "--json", str(out_json),
               "--html", str(out_html))
    assert res.exit_code == 0, res.output
    _check_intel(json.loads(out_json.read_text(encoding="utf-8"))["intelligence"])
    assert all(t in out_html.read_text(encoding="utf-8") for t in SECTIONS)


async def test_live_scan_report_includes_intel_without_db(mock_site: str) -> None:
    ctx = await Pipeline(_cfg()).run(mock_site)  # --no-db path: no storage at all
    rep = build_report(ctx)
    _check_intel(rep["intelligence"])
    json.dumps(rep)  # fully JSON-serializable
    html = render_html(rep, collect_extras(ctx))
    for title in SECTIONS:
        assert title in html


def test_html_intel_sections_escape_hostile_values() -> None:
    intel = {
        "summary": {"endpoints": 1, "observed": 1, "static_only": 0, "parameters": 1,
                    "sensitive_parameters": 1, "auth_kind": "unknown",
                    "attack_surface_findings": 0},
        "attack_surface": {"id": "x", "label": "<script>alert(1)</script>", "type": "domain",
                           "children": [], "findings": [], "max_severity": None,
                           "finding_count": 0, "props": {}},
        "endpoints": [{"url": "https://x/<img src=x onerror=alert(1)>", "method": "GET",
                       "kind": "rest", "observation": "observed", "discovery_status": "",
                       "sources": [], "params": ["<b>p</b>"], "sensitive_params": []}],
        "parameters": [{"name": "<i>n</i>", "classification": "redirect", "confidence": 0.9,
                        "locations": ["query"], "endpoint_count": 1, "endpoints": ["https://x/"],
                        "sensitive": True}],
        "auth_flow": {"kind": "unknown", "confidence": 0.3, "steps": ["<svg onload=1>"],
                      "has_login_form": False, "has_session_cookie": False, "endpoints": []},
    }
    html = render_html({"scan_id": "abcd1234", "target": {"base_url": "https://x",
                        "hostname": "x"}, "intelligence": intel})
    for raw in ("<script>alert(1)</script>", "<img src=x onerror", "<b>p</b>", "<i>n</i>",
                "<svg onload=1>"):
        assert raw not in html
    assert "&lt;script&gt;" in html
