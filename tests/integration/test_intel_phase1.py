"""Integration: AST endpoints + source-map reconstruction on the mock site."""

from __future__ import annotations

from webrecon.core.config import ScanConfig, ScopeMode
from webrecon.modules.javascript.ast_js import node_available
from webrecon.pipeline import Pipeline


def _cfg() -> ScanConfig:
    c = ScanConfig()
    c.scope.allow_private_targets = True
    c.scope.mode = ScopeMode.SAME_ORIGIN
    c.rate.requests_per_second = 100
    c.http.verify_tls = False
    return c


async def test_sourcemap_reconstructed_and_masked(mock_site: str) -> None:
    ctx = await Pipeline(_cfg()).run(mock_site)
    js = ctx.results["javascript"]
    checks = {f.check_id for f in js.findings}
    assert "exposure.sourcemap.reconstructed" in checks  # mock .map has sourcesContent
    rec = next(f for f in js.findings if f.check_id == "exposure.sourcemap.reconstructed")
    blob = str(rec.evidence[0].data)
    # the reconstructed AWS key must be masked, never leaked verbatim
    assert "AKIAZZZZ1111WWWW2222" not in blob
    assert any(s["kind"] == "aws_access_key" for s in rec.evidence[0].data["secrets"])


async def test_ast_endpoints_carry_methods(mock_site: str) -> None:
    if not node_available():
        return  # AST layer is an enrichment; skip when Node/acorn absent
    ctx = await Pipeline(_cfg()).run(mock_site)
    eps = ctx.results["api"].data["endpoints"]
    # the mock app.js does fetch("/api/admin/settings") → AST yields a GET method
    methoded = [e for e in eps if e.get("methods")]
    assert methoded, "expected at least one endpoint with an AST-derived method"
    # endpoints now carry parameter intelligence + discovery status
    assert all("discovery_status" in e for e in eps)
    assert all(isinstance(e.get("params"), list) for e in eps)
