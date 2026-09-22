"""Crawler integration against the local mock site (§7/§16/§17)."""

from __future__ import annotations

from sqlalchemy import select

from webrecon.core.config import ScanConfig, ScopeMode
from webrecon.core.enums import ModuleStatus
from webrecon.pipeline import Pipeline
from webrecon.storage.database import Database
from webrecon.storage.models import Asset, Form, Page


def _lab_config() -> ScanConfig:
    cfg = ScanConfig()
    cfg.scope.allow_private_targets = True
    cfg.scope.mode = ScopeMode.SAME_ORIGIN
    cfg.rate.requests_per_second = 100
    cfg.http.verify_tls = False
    return cfg


async def test_crawler_discovers_in_scope_pages(mock_site: str) -> None:
    ctx = await Pipeline(_lab_config()).run(mock_site)
    crawl = ctx.results["crawler"]
    assert crawl.status == ModuleStatus.SUCCESS
    inv = ctx.shared["inventory"]
    crawled = {p.url for p in inv.pages}
    assert any(u.rstrip("/") == mock_site for u in crawled)  # root, slash-insensitive
    assert mock_site + "/about" in crawled
    assert mock_site + "/contact" in crawled


async def test_crawler_respects_robots(mock_site: str) -> None:
    ctx = await Pipeline(_lab_config()).run(mock_site)
    inv = ctx.shared["inventory"]
    crawled = {p.url for p in inv.pages}
    # /admin is linked from index but Disallowed in robots.txt.
    assert mock_site + "/admin" not in crawled
    assert inv.stats.get("robots_skipped", 0) >= 1


async def test_crawler_stays_in_scope(mock_site: str) -> None:
    ctx = await Pipeline(_lab_config()).run(mock_site)
    inv = ctx.shared["inventory"]
    crawled = {p.url for p in inv.pages}
    assert not any("third-party.example" in u for u in crawled)


async def test_crawler_records_assets_and_forms(mock_site: str) -> None:
    ctx = await Pipeline(_lab_config()).run(mock_site)
    inv = ctx.shared["inventory"]
    asset_urls = {a.url for a in inv.assets}
    assert mock_site + "/static/app.js" in asset_urls
    assert len(inv.forms) >= 1
    assert any(f.action and f.action.endswith("/search") for f in inv.forms)


async def test_crawler_parses_sitemap(mock_site: str) -> None:
    ctx = await Pipeline(_lab_config()).run(mock_site)
    inv = ctx.shared["inventory"]
    assert any(u.endswith("/only-in-sitemap") for u in inv.sitemap_urls)


async def test_crawler_persists_inventory(mock_site: str) -> None:
    db = Database("sqlite+aiosqlite:///:memory:")
    await db.create_all()
    try:
        await Pipeline(_lab_config(), db=db).run(mock_site)
        async with db.session() as s:
            pages = (await s.execute(select(Page))).scalars().all()
            assets = (await s.execute(select(Asset))).scalars().all()
            forms = (await s.execute(select(Form))).scalars().all()
            assert len(pages) >= 3
            assert len(assets) >= 1
            assert len(forms) >= 1
    finally:
        await db.dispose()
