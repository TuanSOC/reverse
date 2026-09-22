"""Technology module integration against the mock site (§10)."""

from __future__ import annotations

from sqlalchemy import select

from webrecon.core.config import ScanConfig, ScopeMode
from webrecon.core.enums import ModuleStatus
from webrecon.pipeline import Pipeline
from webrecon.storage.database import Database
from webrecon.storage.models import Technology


def _lab_config() -> ScanConfig:
    cfg = ScanConfig()
    cfg.scope.allow_private_targets = True
    cfg.scope.mode = ScopeMode.SAME_ORIGIN
    cfg.rate.requests_per_second = 100
    cfg.http.verify_tls = False
    return cfg


async def test_detects_expected_stack(mock_site: str) -> None:
    ctx = await Pipeline(_lab_config()).run(mock_site)
    tech = ctx.results["technology"]
    assert tech.status == ModuleStatus.SUCCESS
    names = {t["name"] for t in tech.data["technologies"]}
    assert "Nginx" in names
    assert "PHP" in names
    assert "WordPress" in names


async def test_technology_persisted(mock_site: str) -> None:
    db = Database("sqlite+aiosqlite:///:memory:")
    await db.create_all()
    try:
        await Pipeline(_lab_config(), db=db).run(mock_site)
        async with db.session() as s:
            rows = (await s.execute(select(Technology))).scalars().all()
            by_name = {r.name: r for r in rows}
            assert "WordPress" in by_name
            assert by_name["WordPress"].version == "6.4.2"
            assert by_name["Nginx"].version == "1.25.3"
    finally:
        await db.dispose()
