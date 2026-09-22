"""Exposure module: well-known, risky methods, opt-in sensitive probes (§21)."""

from __future__ import annotations

from webrecon.core.config import ScanConfig, ScopeMode
from webrecon.core.enums import ModuleStatus
from webrecon.pipeline import Pipeline


def _cfg(probe: bool = False) -> ScanConfig:
    c = ScanConfig()
    c.scope.allow_private_targets = True
    c.scope.mode = ScopeMode.SAME_ORIGIN
    c.rate.requests_per_second = 100
    c.http.verify_tls = False
    c.probe = probe
    return c


async def test_flags_missing_securitytxt_and_risky_methods(mock_site: str) -> None:
    ctx = await Pipeline(_cfg()).run(mock_site)
    exp = ctx.results["exposure"]
    assert exp.status == ModuleStatus.SUCCESS
    checks = {f.check_id for f in exp.findings}
    assert "exposure.securitytxt.missing" in checks  # mock has none
    assert "exposure.methods.risky" in checks  # mock OPTIONS advertises TRACE


async def test_sensitive_probe_off_by_default(mock_site: str) -> None:
    ctx = await Pipeline(_cfg(probe=False)).run(mock_site)
    checks = {f.check_id for f in ctx.results["exposure"].findings}
    assert not any(c.startswith("exposure.file.") for c in checks)


async def test_sensitive_probe_finds_exposed_git_when_enabled(mock_site: str) -> None:
    ctx = await Pipeline(_cfg(probe=True)).run(mock_site)
    checks = {f.check_id for f in ctx.results["exposure"].findings}
    # /.git/HEAD is served by the mock and matches the signature.
    assert any("git" in c for c in checks if c.startswith("exposure.file."))
