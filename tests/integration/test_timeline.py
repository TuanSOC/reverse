"""Integration: persisted scan timeline, JS explorer rows, attack-surface tree (Phase 3)."""

from __future__ import annotations

import asyncio

from fastapi.testclient import TestClient

from webrecon.api.app import create_app
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
    return "sqlite+aiosqlite:///" + str(tmp_path / "t.db").replace("\\", "/")


def _populate(url: str, mock_site: str) -> int:
    async def _run() -> int:
        db = Database(url)
        await db.create_all()
        ctx = await Pipeline(_cfg(), db=db).run(mock_site)
        await db.dispose()
        return len(ctx.events)

    return asyncio.run(_run())


def test_timeline_persisted_and_served(mock_site: str, tmp_path) -> None:
    url = _db_url(tmp_path)
    in_memory = _populate(url, mock_site)

    with TestClient(create_app(url)) as client:
        sid = client.get("/api/scans").json()[0]["id"]
        events = client.get(f"/api/scans/{sid}/timeline").json()

        # every in-memory event reached the DB, in order, contiguous seq
        assert len(events) == in_memory
        assert [e["seq"] for e in events] == list(range(len(events)))
        assert events[0]["kind"] == "scan" and events[0]["label"].startswith("Scan started")
        assert events[-1]["kind"] == "scan" and events[-1]["label"].startswith("Scan finished")

        kinds = {e["kind"] for e in events}
        assert {"module", "discovered", "observed", "finding"} <= kinds
        entities = {e["data"].get("entity") for e in events}
        assert {"target", "page", "endpoint", "script", "technology"} <= entities

        # one finding event per stored finding, attributed to a module
        findings = client.get(f"/api/scans/{sid}/findings").json()
        only = client.get(f"/api/scans/{sid}/timeline", params={"kind": "finding"}).json()
        assert len(only) == len(findings)
        assert all(e["kind"] == "finding" and e["module"] for e in only)

        # module events carry status + duration
        mod = next(e for e in events if e["kind"] == "module" and e["module"] == "crawler")
        assert mod["data"]["status"] and "duration_ms" in mod["data"]

        # secrets never leak into the timeline
        raw = client.get(f"/api/scans/{sid}/timeline").text
        assert "AKIAIOSFODNN7EXAMPLE" not in raw and "AKIAZZZZ1111WWWW2222" not in raw


def test_js_files_and_attack_surface(mock_site: str, tmp_path) -> None:
    url = _db_url(tmp_path)
    _populate(url, mock_site)

    with TestClient(create_app(url)) as client:
        sid = client.get("/api/scans").json()[0]["id"]

        js = client.get(f"/api/scans/{sid}/js").json()
        app = next(r for r in js if r["url"].endswith("/static/app.js"))
        assert app["analyzed"] and app["observation"] == "observed"
        assert len(app["sha256"]) == 64 and app["size"] > 0
        assert app["sourcemap_exposed"] and app["reconstructed_files"] >= 1
        assert any("/api/admin/settings" in c.get("url", "") for c in app["ast_calls"])
        assert app["secrets"] >= 1  # a count only — never the value
        assert "AKIAIOSFODNN7EXAMPLE" not in client.get(f"/api/scans/{sid}/js").text

        tree = client.get(f"/api/scans/{sid}/attack-surface").json()
        assert tree["type"] == "domain"
        labels = [c["label"] for c in tree["children"]]
        assert labels[0] == "Web surface"
        total = len(client.get(f"/api/scans/{sid}/findings").json())
        assert 0 < tree["finding_count"] <= total
        assert tree["max_severity"] in ("critical", "high", "medium", "low", "informational")

        # the asset graph now carries the real asset type
        graph = client.get(f"/api/scans/{sid}/graph").json()
        assert any(n["type"] == "asset" and n["props"].get("type") == "script"
                   for n in graph["nodes"])
