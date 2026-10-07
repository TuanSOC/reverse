"""Integration: unified asset graph + auth-flow built from a persisted scan."""

from __future__ import annotations

import asyncio

from webrecon.core.config import ScanConfig, ScopeMode
from webrecon.intel.asset_graph import build_asset_graph
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
    return "sqlite+aiosqlite:///" + str(tmp_path / "g.db").replace("\\", "/")


def test_asset_graph_typed_with_provenance(mock_site: str, tmp_path) -> None:
    url = _db_url(tmp_path)

    async def _run():
        db = Database(url)
        await db.create_all()
        ctx = await Pipeline(_cfg(), db=db).run(mock_site)
        sid = ctx.scan_id
        g = await build_asset_graph(db, sid)
        await db.dispose()
        return g

    g = asyncio.run(_run())
    types = {n.type for n in g.nodes}
    # richer than a flat star: multiple entity types present
    assert "domain" in types
    assert {"endpoint", "technology"} & types
    # every node carries provenance (a discovery source)
    assert all(isinstance(n.source, str) for n in g.nodes)
    # edges reference real node ids and use typed relations
    ids = {n.id for n in g.nodes}
    assert all(e.source in ids and e.target in ids for e in g.edges)
    assert any(e.relation in ("USES", "CALLS", "REFERENCES", "CONTAINS") for e in g.edges)
    # dashboard contract preserved
    d = g.to_dict()
    assert "nodes" in d and "edges" in d
    assert all({"id", "label", "type"} <= set(n) for n in d["nodes"])
