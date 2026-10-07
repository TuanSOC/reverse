"""Integration test: auto-login captures a session via the headless browser."""

from __future__ import annotations

from webrecon.core.config import ScanConfig, ScopeMode
from webrecon.pipeline import Pipeline


def _cfg(mock_site: str, user: str, pw: str) -> ScanConfig:
    c = ScanConfig()
    c.scope.allow_private_targets = True
    c.scope.mode = ScopeMode.SAME_ORIGIN
    c.rate.requests_per_second = 100
    c.http.verify_tls = False
    c.auth.login_url = mock_site.rstrip("/") + "/login"
    c.auth.username = user
    c.auth.password = pw
    return c


async def test_auto_login_captures_session(mock_site: str) -> None:
    ctx = await Pipeline(_cfg(mock_site, "admin", "secret")).run(mock_site)
    # The browser logged in and the session cookie was captured + reused.
    assert ctx.shared.get("authenticated") is True
    assert "authsession" in (ctx.config.http.cookie or "")


async def test_auto_login_bad_credentials_no_session(mock_site: str) -> None:
    ctx = await Pipeline(_cfg(mock_site, "admin", "wrong")).run(mock_site)
    # Wrong password → still on a page with a password field → no session captured.
    assert ctx.shared.get("authenticated") is not True
    assert "authsession" not in (ctx.config.http.cookie or "")
