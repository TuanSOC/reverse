"""Integration: the ratelimit module runs in a real scan and its active probe is bounded."""

from __future__ import annotations

from webrecon.core.config import ScanConfig, ScopeMode
from webrecon.modules.ratelimit.module import MAX_PROBE_REQUESTS
from webrecon.pipeline import Pipeline


def _cfg(active: bool) -> ScanConfig:
    c = ScanConfig()
    c.scope.allow_private_targets = True
    c.scope.mode = ScopeMode.SAME_ORIGIN
    c.rate.requests_per_second = 100
    c.http.verify_tls = False
    c.active = active
    return c


async def test_ratelimit_passive_runs_by_default(mock_site: str) -> None:
    ctx = await Pipeline(_cfg(active=False)).run(mock_site)
    res = ctx.results["ratelimit"]
    assert str(res.status) == "success"
    assert res.data["active_probe"] is None  # no probe without --active


async def test_ratelimit_active_probe_is_bounded_and_reports(mock_site: str) -> None:
    ctx = await Pipeline(_cfg(active=True)).run(mock_site)
    res = ctx.results["ratelimit"]
    assert str(res.status) == "success"
    # The mock site does not throttle, so the bounded probe observes no limit.
    assert res.data["active_probe"] in ("none_observed", "inconclusive")
    probe_findings = [f for f in res.findings if f.check_id.startswith("ratelimit.")]
    for f in probe_findings:
        for ev in f.evidence:
            # Hard cap honoured — the probe never floods the target.
            assert len(ev.data.get("statuses", [])) <= MAX_PROBE_REQUESTS
    # A missing rate limit surfaces as a low-severity posture finding.
    assert any(f.check_id == "ratelimit.absent" for f in ctx.all_findings())
