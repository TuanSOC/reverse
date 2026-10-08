"""Unit: regression tests for the v0.4.0 /code-review findings (#3 #5 #9 #10)."""

from __future__ import annotations

import asyncio
import sys
from types import SimpleNamespace

import httpx
import pytest

from webrecon.core.config import ScanConfig
from webrecon.core.context import ScanContext
from webrecon.intel.ai import AiError, GroqAnalyzer, assemble_context
from webrecon.intel.auth_flow import is_session_cookie
from webrecon.modules.api.classify import EndpointAggregator
from webrecon.modules.api.module import ApiDiscoveryModule
from webrecon.modules.javascript import ast_js
from webrecon.modules.javascript.module import JS_ANALYSIS_KEY

# -- #3 Groq error bodies of any shape -------------------------------------------


def _ctx():
    return assemble_context(
        "s", overview={"target": {"base_url": "https://ex.com"}, "modules": []},
        findings=[], endpoints=[], js_files=[], forms=[], auth_flow={}, page_count=0)


@pytest.mark.parametrize(("status", "kwargs", "expect"), [
    (429, {"json": {"error": "rate limited"}}, "rate limited"),
    (503, {"json": ["upstream", "down"]}, "503"),
    (502, {"json": "bad gateway"}, "bad gateway"),
    (500, {"text": "<html>oops</html>"}, "oops"),
    (400, {"json": {"error": {"message": "bad model"}}}, "bad model"),
])
def test_groq_any_error_shape_is_ai_error(status: int, kwargs: dict, expect: str) -> None:
    g = GroqAnalyzer("gsk_x1234567890", transport=httpx.MockTransport(
        lambda req: httpx.Response(status, **kwargs)))
    with pytest.raises(AiError) as exc:
        asyncio.run(g.analyze(_ctx()))
    assert str(status) in str(exc.value) and expect in str(exc.value)


# -- #5 node is killed on timeout --------------------------------------------------


def test_extract_calls_kills_process_on_timeout(monkeypatch, tmp_path) -> None:
    slow = tmp_path / "slow.py"
    slow.write_text("import time\ntime.sleep(30)\n", encoding="utf-8")
    monkeypatch.setattr(ast_js, "_NODE", sys.executable)
    monkeypatch.setattr(ast_js, "_EXTRACT_JS", slow)
    monkeypatch.setattr(ast_js, "_TIMEOUT", 0.5)
    procs = []
    real = asyncio.create_subprocess_exec

    async def spy(*args, **kw):
        p = await real(*args, **kw)
        procs.append(p)
        return p

    monkeypatch.setattr(ast_js.asyncio, "create_subprocess_exec", spy)
    assert asyncio.run(ast_js.extract_calls("fetch('/x')")) == []
    assert procs and procs[0].returncode is not None  # reaped, not orphaned


def test_extract_calls_kills_process_on_cancel(monkeypatch, tmp_path) -> None:
    slow = tmp_path / "slow.py"
    slow.write_text("import time\ntime.sleep(30)\n", encoding="utf-8")
    monkeypatch.setattr(ast_js, "_NODE", sys.executable)
    monkeypatch.setattr(ast_js, "_EXTRACT_JS", slow)
    procs = []
    real = asyncio.create_subprocess_exec

    async def spy(*args, **kw):
        p = await real(*args, **kw)
        procs.append(p)
        return p

    monkeypatch.setattr(ast_js.asyncio, "create_subprocess_exec", spy)

    async def scenario():
        task = asyncio.create_task(ast_js.extract_calls("fetch('/x')"))
        await asyncio.sleep(0.5)
        task.cancel()  # what a module timeout / scan cancel does
        with pytest.raises(asyncio.CancelledError):
            await task

    asyncio.run(scenario())
    assert procs and procs[0].returncode is not None


# -- #9 AST placeholders in the base/host are not endpoints -------------------------


def test_ast_placeholder_base_not_added() -> None:
    ctx = ScanContext(config=ScanConfig())
    ctx.shared[JS_ANALYSIS_KEY] = [SimpleNamespace(
        endpoints=[], urls=[], websockets=[],
        ast_calls=[{"url": "{apiBase}/users", "method": "GET"},
                   {"url": "https://{host}/v1/x", "method": "GET"},
                   {"url": "/{tenant}/orders", "method": "GET"},  # constant-built: kept
                   {"url": "/api/users/{id}", "method": "GET"},
                   {"url": "/api/items", "method": "POST"}])]
    agg = EndpointAggregator(base_host="ex.com")
    ApiDiscoveryModule()._from_javascript(ctx, agg, "https://ex.com/")
    urls = {e.url for e in agg.endpoints()}
    assert urls == {"https://ex.com/api/users/{id}", "https://ex.com/api/items",
                    "https://ex.com/{tenant}/orders"}


# -- #10 session-cookie detection -----------------------------------------------------


@pytest.mark.parametrize(("name", "expected"), [
    ("PHPSESSID", True), ("JSESSIONID", True), ("laravel_session", True),
    ("connect.sid", True), ("ASP.NET_SessionId", True), ("sessionid", True),
    ("auth_token", True), ("wordpress_logged_in_abc", True),
    ("SESS3f2a9c1d", True), ("SSESS3f2a9c1d", True), ("ASPSESSIONIDQAQBRTCA", True),
    (".ASPXAUTH", True), ("sessionToken", True), ("accessToken", True), ("CFTOKEN", True),
    ("visid_incap_123", False), ("csrftoken", False), ("XSRF-TOKEN", False),
    ("_ga", False), ("consider", False), ("", False),
])
def test_is_session_cookie(name: str, expected: bool) -> None:
    assert is_session_cookie(name) is expected


# -- #4 post-scan AI ordering + early provider validation ---------------------------


def test_done_is_signalled_before_ai_runs(monkeypatch) -> None:
    from webrecon.api.app import _SimpleManager
    from webrecon.core.context import CancellationToken

    mgr = _SimpleManager(db=None)  # type: ignore[arg-type]
    q = mgr.subscribe("sid")
    seen: list = []

    async def fake_analyze(db, scan_id, provider=None):
        seen.append(("ai", q.qsize(), scan_id in mgr.ai_running))

    monkeypatch.setattr("webrecon.intel.ai.analyze_scan", fake_analyze)

    class _Pipe:
        async def run(self, url, **kw):
            return None

    asyncio.run(mgr._run(_Pipe(), "http://x", "sid", CancellationToken(), "stub"))
    # `_done` was already queued when the AI step started, and running was flagged
    assert seen == [("ai", 1, True)]
    assert q.get_nowait()["module"] == "_done"
    assert "sid" not in mgr.ai_running


def test_cli_rejects_bad_ai_provider_before_scanning() -> None:
    from typer.testing import CliRunner

    from webrecon.cli.app import app as cli

    res = CliRunner().invoke(cli, ["scan", "http://203.0.113.1/", "--ai",
                                   "--ai-provider", "nope", "--no-robots"])
    assert res.exit_code == 2
    assert "AI analysis unavailable" in res.output
    assert "Scan " not in res.output  # never reached the scan summary
