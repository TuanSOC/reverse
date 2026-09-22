"""Browser-mode integration (§20). Opt-in; requires Playwright + Chromium."""

from __future__ import annotations

import pytest

from webrecon.core.config import ScanConfig, ScopeMode
from webrecon.core.enums import ModuleStatus
from webrecon.modules.browser.module import BROWSER_ENDPOINTS_KEY
from webrecon.pipeline import Pipeline

playwright = pytest.importorskip("playwright.async_api")


def _browser_config() -> ScanConfig:
    cfg = ScanConfig()
    cfg.scope.allow_private_targets = True
    cfg.scope.mode = ScopeMode.SAME_ORIGIN
    cfg.rate.requests_per_second = 100
    cfg.http.verify_tls = False
    cfg.browser_mode = True
    cfg.browser.screenshots = False  # keep the test light
    return cfg


async def test_browser_observes_xhr_endpoint(mock_site: str) -> None:
    # app.js runs fetch("/api/admin/settings") on load -> observed via the browser.
    try:
        ctx = await Pipeline(_browser_config()).run(mock_site)
    except Exception as exc:  # pragma: no cover - environment without a usable browser
        pytest.skip(f"browser unavailable: {exc}")

    browser = ctx.results["browser"]
    if browser.status != ModuleStatus.SUCCESS:
        pytest.skip(f"browser did not run: {browser.error}")

    observed = {e["url"] for e in ctx.shared.get(BROWSER_ENDPOINTS_KEY, [])}
    assert any("/api/admin/settings" in u for u in observed)

    # And the API module should now classify it as observed.
    api = ctx.results["api"]
    eps = {e["url"]: e for e in api.data["endpoints"]}
    settings = mock_site + "/api/admin/settings"
    assert eps.get(settings, {}).get("observation") == "observed"
