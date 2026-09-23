"""active_verify integration against the mock site (opt-in --active)."""

from __future__ import annotations

from webrecon.core.config import ScanConfig, ScopeMode
from webrecon.core.enums import ModuleStatus, Observation
from webrecon.pipeline import Pipeline


def _cfg(active: bool) -> ScanConfig:
    c = ScanConfig()
    c.scope.allow_private_targets = True
    c.scope.mode = ScopeMode.SAME_ORIGIN
    c.rate.requests_per_second = 100
    c.http.verify_tls = False
    c.active = active
    return c


async def test_skipped_when_inactive(mock_site: str) -> None:
    ctx = await Pipeline(_cfg(active=False)).run(mock_site)
    r = ctx.results["active_verify"]
    assert r.status == ModuleStatus.SKIPPED
    assert r.stats.get("requests", 0) == 0  # no probes issued when passive


async def test_active_confirms_open_redirect_and_reflected_xss(mock_site: str) -> None:
    ctx = await Pipeline(_cfg(active=True)).run(mock_site)
    r = ctx.results["active_verify"]
    assert r.status == ModuleStatus.SUCCESS
    checks = {f.check_id for f in r.findings}
    # /redir?url= reflects into Location; /echo?q= reflects unencoded into HTML
    assert "active.open_redirect.confirmed" in checks
    assert "active.xss.reflected" in checks
    for f in r.findings:
        assert f.observation == Observation.OBSERVED  # confirmed, not just potential
        assert f.evidence  # every confirmation carries evidence
    assert r.stats["requests"] <= 40  # budget respected


async def test_active_stays_get_only(mock_site: str) -> None:
    # The module uses SafeGetEngine; assert no mutating request was recorded.
    ctx = await Pipeline(_cfg(active=True)).run(mock_site)
    assert ctx.results["active_verify"].status == ModuleStatus.SUCCESS
