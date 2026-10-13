"""Integration: deleting a scan removes all its data (API, repository, CLI)."""

from __future__ import annotations

import asyncio

from fastapi.testclient import TestClient
from sqlalchemy import func, select
from typer.testing import CliRunner

from webrecon.api.app import create_app
from webrecon.cli.app import app as cli
from webrecon.core.config import ScanConfig, ScopeMode
from webrecon.pipeline import Pipeline
from webrecon.storage import models
from webrecon.storage.database import Database
from webrecon.storage.repository import ScanRepository

# every scan-scoped table must be empty after a delete
_SCOPED = [
    models.ModuleRun, models.RequestRecord, models.ResponseRecord, models.Page,
    models.Asset, models.Technology, models.DnsRecord, models.IpIntelRecord,
    models.Certificate, models.Endpoint, models.Form, models.Cookie,
    models.FindingRecord, models.EvidenceRecord, models.ScanEventRecord,
    models.AiAnalysisRecord,
]


def _cfg() -> ScanConfig:
    c = ScanConfig()
    c.scope.allow_private_targets = True
    c.scope.mode = ScopeMode.SAME_ORIGIN
    c.rate.requests_per_second = 100
    c.http.verify_tls = False
    return c


def _db_url(tmp_path) -> str:
    return "sqlite+aiosqlite:///" + str(tmp_path / "del.db").replace("\\", "/")


async def _counts(db: Database, scan_id: str) -> dict[str, int]:
    async with db.session() as s:
        out = {}
        for m in _SCOPED:
            out[m.__name__] = await s.scalar(
                select(func.count()).select_from(m).where(m.scan_id == scan_id))  # type: ignore[attr-defined]
        out["Scan"] = await s.scalar(
            select(func.count()).select_from(models.Scan).where(models.Scan.id == scan_id))
    return out


def test_repository_delete_removes_everything(mock_site: str, tmp_path) -> None:
    url = _db_url(tmp_path)

    async def _run():
        db = Database(url)
        await db.create_all()
        ctx = await Pipeline(_cfg(), db=db).run(mock_site)
        sid = ctx.scan_id
        before = await _counts(db, sid)
        # also store an AI analysis so that table is exercised
        from webrecon.intel.ai import analyze_scan
        await analyze_scan(db, sid, provider="stub")
        ok = await ScanRepository(db).delete_scan(sid)
        ok2 = await ScanRepository(db).delete_scan(sid)  # second time: already gone
        after = await _counts(db, sid)
        async with db.session() as s:
            targets = await s.scalar(select(func.count()).select_from(models.Target))
        await db.dispose()
        return before, after, ok, ok2, targets

    before, after, ok, ok2, targets = asyncio.run(_run())
    assert ok is True and ok2 is False
    assert before["FindingRecord"] > 0 and before["Endpoint"] > 0  # data existed
    assert all(v == 0 for v in after.values())                     # all gone
    assert targets == 0                                            # orphan target removed


def test_api_delete_scan(mock_site: str, tmp_path) -> None:
    url = _db_url(tmp_path)

    async def _populate():
        db = Database(url)
        await db.create_all()
        await Pipeline(_cfg(), db=db).run(mock_site)
        await db.dispose()

    asyncio.run(_populate())
    with TestClient(create_app(url)) as client:
        sid = client.get("/api/scans").json()[0]["id"]
        assert client.delete(f"/api/scans/{sid}").json() == {"deleted": True}
        assert client.get("/api/scans").json() == []
        assert client.delete(f"/api/scans/{sid}").status_code == 404
        # a running scan cannot be deleted
        client.app.state.manager.status["busy"] = "running"
        assert client.delete("/api/scans/busy").status_code == 409


def test_cli_delete_scan(mock_site: str, tmp_path) -> None:
    url = _db_url(tmp_path)

    async def _populate() -> str:
        db = Database(url)
        await db.create_all()
        ctx = await Pipeline(_cfg(), db=db).run(mock_site)
        await db.dispose()
        return ctx.scan_id

    sid = asyncio.run(_populate())
    r = CliRunner().invoke(cli, ["delete", sid[:8], "--yes", "--database-url", url])
    assert r.exit_code == 0 and "Deleted" in r.output
    assert CliRunner().invoke(
        cli, ["delete", sid[:8], "--yes", "--database-url", url]).exit_code == 1
