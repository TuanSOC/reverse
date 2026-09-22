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
        # v0.3.0: IP intelligence surfaced on the overview (loopback → minimal)
        assert "ip_intel" in overview
        assert overview["ip_intel"]["ips"][0]["ip"] == "127.0.0.1"

        findings = client.get(f"/api/scans/{sid}/findings").json()
        assert findings
        assert findings[0]["evidence"]  # each finding carries evidence

        endpoints = client.get(f"/api/scans/{sid}/endpoints").json()
        assert any(e["observation"] == "observed" for e in endpoints)
        # detail fields the drawer relies on are present
        assert "meta" in endpoints[0]
        assets = client.get(f"/api/scans/{sid}/assets").json()
        assert assets and "meta" in assets[0] and "content_hash" in assets[0]
        pages = client.get(f"/api/scans/{sid}/pages").json()
        assert pages and "discovered_from" in pages[0]

        techs = client.get(f"/api/scans/{sid}/technologies").json()
        assert any(t["name"] == "WordPress" for t in techs)

        graph = client.get(f"/api/scans/{sid}/graph").json()
        assert graph["nodes"] and graph["edges"]

        forms = client.get(f"/api/scans/{sid}/forms").json()
        assert isinstance(forms, list) and forms  # the mock has a search form

        # report formats
        full = client.get(f"/api/scans/{sid}/report.json").json()
        assert full["scan_id"] == sid
        # min_severity filter keeps only high+ findings and recomputes summary
        hi = client.get(
            f"/api/scans/{sid}/report.json", params={"min_severity": "high"}
        ).json()
        assert all(
            f["severity"] in ("high", "critical") for f in hi["findings"]
        )
        assert hi["summary"]["total_findings"] == len(hi["findings"])
        assert hi["summary"]["min_severity"] == "high"
        assert len(hi["findings"]) <= len(full["findings"])
        html = client.get(f"/api/scans/{sid}/report.html")
        assert html.status_code == 200 and "Executive Summary" in html.text
        pdf = client.get(f"/api/scans/{sid}/report.pdf")
        assert pdf.status_code == 200 and pdf.content[:4] == b"%PDF"

        # diff a scan against itself → no changes
        d = client.get(f"/api/scans/{sid}/diff", params={"against": sid}).json()
        assert d["endpoints"]["added"] == [] and d["endpoints"]["removed"] == []

        # cancel on a finished scan is a no-op (not running)
        assert client.post(f"/api/scans/{sid}/cancel").json() == {"cancelled": False}

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
