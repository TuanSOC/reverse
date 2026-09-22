"""JavaScript module integration against the mock site (§8/§9)."""

from __future__ import annotations

from webrecon.core.config import ScanConfig, ScopeMode
from webrecon.core.enums import ModuleStatus
from webrecon.modules.javascript.module import JS_ANALYSIS_KEY
from webrecon.pipeline import Pipeline


def _lab_config() -> ScanConfig:
    cfg = ScanConfig()
    cfg.scope.allow_private_targets = True
    cfg.scope.mode = ScopeMode.SAME_ORIGIN
    cfg.rate.requests_per_second = 100
    cfg.http.verify_tls = False
    return cfg


async def test_js_module_analyzes_and_extracts(mock_site: str) -> None:
    ctx = await Pipeline(_lab_config()).run(mock_site)
    js = ctx.results["javascript"]
    assert js.status == ModuleStatus.SUCCESS
    assert js.data["files_analyzed"] >= 1
    assert js.data["total_endpoints"] >= 2
    analyses = ctx.shared[JS_ANALYSIS_KEY]
    endpoints = {e for a in analyses for e in a.endpoints}
    assert "/api/v1/users" in endpoints
    assert "/api/admin/settings" in endpoints


async def test_js_module_flags_exposed_source_map(mock_site: str) -> None:
    ctx = await Pipeline(_lab_config()).run(mock_site)
    checks = {f.check_id for f in ctx.results["javascript"].findings}
    assert "exposure.sourcemap.exposed" in checks


async def test_js_module_flags_secret_but_masks_it(mock_site: str) -> None:
    ctx = await Pipeline(_lab_config()).run(mock_site)
    secret_findings = [
        f for f in ctx.results["javascript"].findings if f.check_id.startswith("exposure.secret")
    ]
    assert secret_findings
    # The AWS example key must be masked everywhere in evidence.
    for f in secret_findings:
        for ev in f.evidence:
            assert "AKIAIOSFODNN7EXAMPLE" not in str(ev.data)


async def test_js_endpoints_are_referenced_not_observed(mock_site: str) -> None:
    # P6 must not assert endpoints exist; they are for P7 to classify/probe.
    ctx = await Pipeline(_lab_config()).run(mock_site)
    analyses = ctx.shared[JS_ANALYSIS_KEY]
    assert any(a.endpoints for a in analyses)
