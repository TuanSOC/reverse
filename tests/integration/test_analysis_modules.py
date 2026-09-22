"""Headers/cookies/cors modules against the local mock site (§13/§14/§15)."""

from __future__ import annotations

from webrecon.core.config import ScanConfig, ScopeMode
from webrecon.core.enums import ModuleStatus
from webrecon.pipeline import Pipeline
from webrecon.reporting.json_report import build_report


def _lab_config() -> ScanConfig:
    cfg = ScanConfig()
    cfg.scope.allow_private_targets = True
    cfg.scope.mode = ScopeMode.SAME_ORIGIN
    cfg.rate.requests_per_second = 100
    cfg.http.verify_tls = False
    return cfg


async def test_headers_module_flags_missing_headers(mock_site: str) -> None:
    ctx = await Pipeline(_lab_config()).run(mock_site)
    checks = {f.check_id for f in ctx.results["headers"].findings}
    assert "headers.csp.missing" in checks
    assert "headers.xcto.missing" in checks
    # HSTS is https-only; the mock is plain HTTP so it must NOT be flagged here.
    assert "headers.hsts.missing" not in checks
    # Server header discloses a version.
    assert any(c.startswith("headers.disclosure") for c in checks)


async def test_cookies_module_flags_bare_session_cookie(mock_site: str) -> None:
    ctx = await Pipeline(_lab_config()).run(mock_site)
    checks = {f.check_id for f in ctx.results["cookies"].findings}
    assert "cookies.httponly.missing" in checks  # sessionid without HttpOnly
    assert "cookies.samesite.missing" in checks
    # The masked value must not leak the real cookie value anywhere.
    report = build_report(ctx)
    assert "secretvalue123" not in str(report)


async def test_cors_module_flags_wildcard(mock_site: str) -> None:
    ctx = await Pipeline(_lab_config()).run(mock_site)
    checks = {f.check_id for f in ctx.results["cors"].findings}
    assert "cors.wildcard_origin" in checks


async def test_dns_and_tls_skip_on_ip_literal(mock_site: str) -> None:
    ctx = await Pipeline(_lab_config()).run(mock_site)
    assert ctx.results["dns"].status == ModuleStatus.SKIPPED
    assert ctx.results["tls"].status == ModuleStatus.SKIPPED
