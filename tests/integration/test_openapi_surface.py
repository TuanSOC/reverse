"""Integration: OpenAPI spec via the API and CLI for a real scan."""

from __future__ import annotations

import asyncio
import json

import yaml
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
    return "sqlite+aiosqlite:///" + str(tmp_path / "oa.db").replace("\\", "/")


def _populate(url: str, mock_site: str) -> None:
    async def _run():
        db = Database(url)
        await db.create_all()
        await Pipeline(_cfg(), db=db).run(mock_site)
        await db.dispose()

    asyncio.run(_run())


def test_api_openapi_json_and_yaml(mock_site: str, tmp_path) -> None:
    url = _db_url(tmp_path)
    _populate(url, mock_site)
    with TestClient(create_app(url)) as client:
        sid = client.get("/api/scans").json()[0]["id"]
        r = client.get(f"/api/scans/{sid}/openapi.json")
        assert r.status_code == 200
        doc = r.json()
        assert doc["openapi"] == "3.1.0" and doc["paths"]
        assert "attachment" in r.headers.get("content-disposition", "")
        # the mock site exposes /api/item?id= and /api/search?q=
        assert any(p.startswith("/api/") for p in doc["paths"])

        y = client.get(f"/api/scans/{sid}/openapi.yaml")
        assert y.status_code == 200 and yaml.safe_load(y.text)["openapi"] == "3.1.0"
        assert client.get(f"/api/scans/{sid}/openapi.xml").status_code == 400


def test_cli_openapi(mock_site: str, tmp_path) -> None:
    url = _db_url(tmp_path)
    _populate(url, mock_site)
    out = tmp_path / "spec.json"
    r = CliRunner().invoke(cli, ["openapi", "--out", str(out), "--database-url", url])
    assert r.exit_code == 0, r.output
    doc = json.loads(out.read_text(encoding="utf-8"))
    assert doc["openapi"] == "3.1.0" and doc["paths"]
    # stdout YAML form
    y = CliRunner().invoke(cli, ["openapi", "--yaml", "--database-url", url])
    assert y.exit_code == 0 and "openapi: 3.1.0" in y.output
