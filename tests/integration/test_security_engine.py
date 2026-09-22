"""Security engine integration against the mock site (§21/§23)."""

from __future__ import annotations

from webrecon.core.config import ScanConfig, ScopeMode
from webrecon.core.enums import ModuleStatus
from webrecon.modules.security.module import RISK_SUMMARY_KEY
from webrecon.pipeline import Pipeline
from webrecon.reporting.json_report import build_report


def _lab_config() -> ScanConfig:
    cfg = ScanConfig()
    cfg.scope.allow_private_targets = True
    cfg.scope.mode = ScopeMode.SAME_ORIGIN
    cfg.rate.requests_per_second = 100
    cfg.http.verify_tls = False
    return cfg


async def test_security_module_classifies_risk(mock_site: str) -> None:
    ctx = await Pipeline(_lab_config()).run(mock_site)
    sec = ctx.results["security"]
    assert sec.status == ModuleStatus.SUCCESS
    summary = ctx.shared[RISK_SUMMARY_KEY]
    # The mock is plain HTTP (high-severity transport finding) -> high risk.
    assert summary.level == "high"
    assert summary.total >= 1


async def test_security_flags_outdated_jquery(mock_site: str) -> None:
    ctx = await Pipeline(_lab_config()).run(mock_site)
    checks = {f.check_id for f in ctx.results["security"].findings}
    assert "technology.outdated.jquery" in checks


async def test_report_includes_risk(mock_site: str) -> None:
    ctx = await Pipeline(_lab_config()).run(mock_site)
    report = build_report(ctx)
    assert report["risk"] is not None
    assert report["risk"]["level"] == "high"
