"""Integration: the public/demo read-only mode refuses every write."""

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
    return "sqlite+aiosqlite:///" + str(tmp_path / "ro.db").replace("\\", "/")


def _populate(url: str, mock_site: str) -> str:
    async def _run() -> str:
        db = Database(url)
        await db.create_all()
        await Pipeline(_cfg(), db=db).run(mock_site)
        from webrecon.api import queries

        scans = await queries.list_scans(db)
        await db.dispose()
        return scans[0]["id"]

    return asyncio.run(_run())


def test_read_only_allows_reads_blocks_writes(mock_site: str, tmp_path) -> None:
    url = _db_url(tmp_path)
    sid = _populate(url, mock_site)
    with TestClient(create_app(url, read_only=True)) as client:
        # meta advertises the mode so the dashboard can hide its controls
        meta = client.get("/api/meta").json()
        assert meta["read_only"] is True

        # reads still work: stored scans remain fully viewable
        assert client.get("/api/scans").status_code == 200
        assert client.get(f"/api/scans/{sid}").status_code == 200
        assert client.get(f"/api/scans/{sid}/findings").status_code == 200
        assert client.get(f"/api/scans/{sid}/openapi.json").status_code == 200

        # every write is refused with 403, including a brand-new scan,
        # a delete, a cancel, and an AI run (which would spend the key)
        assert client.post("/api/scans", json={"url": "http://x"}).status_code == 403
        assert client.delete(f"/api/scans/{sid}").status_code == 403
        assert client.post(f"/api/scans/{sid}/cancel").status_code == 403
        assert client.post(f"/api/scans/{sid}/ai").status_code == 403

        # the scan was not deleted by the refused request
        assert client.get(f"/api/scans/{sid}").status_code == 200


def test_writable_by_default(mock_site: str, tmp_path) -> None:
    url = _db_url(tmp_path)
    _populate(url, mock_site)
    with TestClient(create_app(url)) as client:
        assert client.get("/api/meta").json()["read_only"] is False


def test_read_only_from_env(monkeypatch, mock_site: str, tmp_path) -> None:
    url = _db_url(tmp_path)
    _populate(url, mock_site)
    monkeypatch.setenv("WEBRECON_READ_ONLY", "1")
    with TestClient(create_app(url)) as client:  # no explicit flag -> env wins
        assert client.get("/api/meta").json()["read_only"] is True
        assert client.post("/api/scans", json={"url": "http://x"}).status_code == 403
