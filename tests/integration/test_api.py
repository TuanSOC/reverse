"""Dashboard API tests (§28). Populates a DB via a scan, then reads it back."""

from __future__ import annotations

import asyncio

from fastapi.testclient import TestClient

from webrecon.api.app import create_app
from webrecon.core.config import ScanConfig, ScopeMode
from webrecon.pipeline import Pipeline
from webrecon.storage.database import Database


def _lab_config() -> ScanConfig:
    cfg = ScanConfig()
    cfg.scope.allow_private_targets = True
    cfg.scope.mode = ScopeMode.SAME_ORIGIN
    cfg.rate.requests_per_second = 100
    cfg.http.verify_tls = False
    return cfg


def _db_url(tmp_path) -> str:
    return "sqlite+aiosqlite:///" + str(tmp_path / "api.db").replace("\\", "/")


def test_api_serves_scan_data(mock_site: str, tmp_path) -> None:
    url = _db_url(tmp_path)

    async def _populate() -> None:
        db = Database(url)
        await db.create_all()
        await Pipeline(_lab_config(), db=db).run(mock_site)
        await db.dispose()

    asyncio.run(_populate())

    with TestClient(create_app(url)) as client:
        scans = client.get("/api/scans").json()
        assert scans
        sid = scans[0]["id"]

        overview = client.get(f"/api/scans/{sid}").json()
        assert overview["risk_level"] == "high"
        assert overview["total_findings"] >= 1
        assert any(m["module"] == "security" for m in overview["modules"])

        findings = client.get(f"/api/scans/{sid}/findings").json()
        assert findings
        assert findings[0]["evidence"]  # each finding carries evidence

        endpoints = client.get(f"/api/scans/{sid}/endpoints").json()
        assert any(e["observation"] == "observed" for e in endpoints)

        techs = client.get(f"/api/scans/{sid}/technologies").json()
        assert any(t["name"] == "WordPress" for t in techs)

        graph = client.get(f"/api/scans/{sid}/graph").json()
        assert graph["nodes"] and graph["edges"]

        # 404 for unknown scan
        assert client.get("/api/scans/does-not-exist").status_code == 404

        # dashboard HTML is served
        assert "WEBRECON" in client.get("/").text or "WebRecon" in client.get("/").text


def test_api_secret_values_not_leaked(mock_site: str, tmp_path) -> None:
    url = _db_url(tmp_path)

    async def _populate() -> None:
        db = Database(url)
        await db.create_all()
        await Pipeline(_lab_config(), db=db).run(mock_site)
        await db.dispose()

    asyncio.run(_populate())
    with TestClient(create_app(url)) as client:
        scans = client.get("/api/scans").json()
        findings = client.get(f"/api/scans/{scans[0]['id']}/findings").text
        # The AWS example key must never appear unmasked in the API output.
        assert "AKIAIOSFODNN7EXAMPLE" not in findings
