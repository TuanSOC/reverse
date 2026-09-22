"""API discovery integration against the mock site (§19)."""

from __future__ import annotations

from sqlalchemy import select

from webrecon.core.config import ScanConfig, ScopeMode
from webrecon.core.enums import ModuleStatus
from webrecon.modules.api.module import API_INVENTORY_KEY
from webrecon.pipeline import Pipeline
from webrecon.storage.database import Database
from webrecon.storage.models import Endpoint


def _lab_config() -> ScanConfig:
    cfg = ScanConfig()
    cfg.scope.allow_private_targets = True
    cfg.scope.mode = ScopeMode.SAME_ORIGIN
    cfg.rate.requests_per_second = 100
    cfg.http.verify_tls = False
    return cfg


async def test_api_discovery_classifies_provenance(mock_site: str) -> None:
    ctx = await Pipeline(_lab_config()).run(mock_site)
    api = ctx.results["api"]
    assert api.status == ModuleStatus.SUCCESS
    eps = {e.url: e for e in ctx.shared[API_INVENTORY_KEY]}

    # /api/status was actually fetched and returned JSON -> observed.
    status_url = mock_site + "/api/status"
    assert status_url in eps
    assert str(eps[status_url].observation) == "observed"

    # /api/v1/users only appears in JS -> referenced, never observed.
    users = mock_site + "/api/v1/users"
    assert users in eps
    assert str(eps[users].observation) == "referenced"


async def test_api_discovery_flags_sensitive_referenced(mock_site: str) -> None:
    ctx = await Pipeline(_lab_config()).run(mock_site)
    checks = {f.check_id for f in ctx.results["api"].findings}
    assert "api.sensitive_endpoints.referenced" in checks


async def test_api_endpoints_persisted(mock_site: str) -> None:
    db = Database("sqlite+aiosqlite:///:memory:")
    await db.create_all()
    try:
        await Pipeline(_lab_config(), db=db).run(mock_site)
        async with db.session() as s:
            rows = (await s.execute(select(Endpoint))).scalars().all()
            observations = {r.url: r.observation for r in rows}
            assert observations.get(mock_site + "/api/status") == "observed"
            assert any(o == "referenced" for o in observations.values())
    finally:
        await db.dispose()
