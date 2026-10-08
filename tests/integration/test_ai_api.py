"""Integration: AI analysis over a persisted scan via API + CLI (offline stub only)."""

from __future__ import annotations

import asyncio
import json

from fastapi.testclient import TestClient
from typer.testing import CliRunner

from webrecon.api.app import create_app
from webrecon.cli.app import app as cli
from webrecon.core.config import ScanConfig, ScopeMode
from webrecon.pipeline import Pipeline
from webrecon.storage.database import Database


def _cfg() -> ScanConfig:
    c = ScanConfig()
    c.scope.allow_private_targets = True
    c.scope.mode = ScopeMode.SAME_ORIGIN
    c.rate.requests_per_second = 100
    c.http.verify_tls = False
    return c


def _db_url(tmp_path) -> str:
    return "sqlite+aiosqlite:///" + str(tmp_path / "ai.db").replace("\\", "/")


def _populate(url: str, mock_site: str) -> str:
    async def _run() -> str:
        db = Database(url)
        await db.create_all()
        ctx = await Pipeline(_cfg(), db=db).run(mock_site)
        await db.dispose()
        return ctx.scan_id

    return asyncio.run(_run())


def test_ai_api_stub_roundtrip(mock_site: str, tmp_path) -> None:
    url = _db_url(tmp_path)
    sid = _populate(url, mock_site)

    with TestClient(create_app(url)) as client:
        before = client.get(f"/api/scans/{sid}/ai").json()
        assert before["analysis"] is None
        assert isinstance(before["groq_available"], bool)

        r = client.post(f"/api/scans/{sid}/ai", params={"provider": "stub"})
        assert r.status_code == 200
        a = r.json()["analysis"]
        assert a["provider"] == "stub" and a["app_summary"]["evidence"]
        # every cited ID resolves in the stored evidence snapshot
        cited = set(a["app_summary"]["evidence"])
        for claims in a["sections"].values():
            for c in claims:
                assert c["evidence"]
                cited.update(c["evidence"])
        assert cited == set(a["evidence"])
        assert a["sections"]["components"]  # mock site has a detectable stack

        after = client.get(f"/api/scans/{sid}/ai").json()
        assert after["analysis"]["created_at"] == a["created_at"]

        raw = json.dumps(after)
        assert "AKIAIOSFODNN7EXAMPLE" not in raw and "AKIAZZZZ1111WWWW2222" not in raw

        assert client.post(f"/api/scans/{sid}/ai", params={"provider": "nope"}).status_code == 400
        assert client.post("/api/scans/missing/ai", params={"provider": "stub"}).status_code == 404


def test_ai_cli_stub(mock_site: str, tmp_path) -> None:
    url = _db_url(tmp_path)
    sid = _populate(url, mock_site)
    out = tmp_path / "ai.json"
    res = CliRunner().invoke(cli, ["ai", sid[:8], "--provider", "stub", "--database-url", url,
                                   "--json", str(out)])
    assert res.exit_code == 0, res.output
    assert "AI analysis" in res.output and "stub" in res.output
    assert json.loads(out.read_text(encoding="utf-8"))["provider"] == "stub"

    shown = CliRunner().invoke(cli, ["ai", sid[:8], "--show", "--database-url", url])
    assert shown.exit_code == 0 and "deterministic-v1" in shown.output


def test_start_scan_rejects_bad_ai_provider(tmp_path) -> None:
    with TestClient(create_app(_db_url(tmp_path))) as client:
        r = client.post("/api/scans", json={"url": "http://203.0.113.1/", "ai": True,
                                             "ai_provider": "nope"})
        assert r.status_code == 400 and "unknown AI provider" in r.json()["detail"]
        assert client.get("/api/scans").json() == []  # nothing was started
