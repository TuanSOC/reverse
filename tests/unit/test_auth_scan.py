"""Unit tests for authenticated-scan credential scoping (no network)."""

from __future__ import annotations

from webrecon.core.config import HttpConfig, ScopeConfig, ScopeMode
from webrecon.engine.http_engine import HttpEngine
from webrecon.engine.scope_engine import ScopeEngine


def _engine(cookie=None, headers=None) -> HttpEngine:
    http = HttpConfig(cookie=cookie, auth_headers=headers or {})
    scope = ScopeEngine("example.com", "https://example.com:443",
                         ScopeConfig(mode=ScopeMode.SAME_DOMAIN))
    return HttpEngine(http, rate_limiter=None, ssrf_guard=None, scope=scope)  # type: ignore[arg-type]


def test_cookie_sent_to_target_host() -> None:
    h = _engine(cookie="session=abc")._auth_headers_for("example.com")
    assert h == {"Cookie": "session=abc"}


def test_cookie_sent_to_subdomain() -> None:
    h = _engine(cookie="session=abc")._auth_headers_for("app.example.com")
    assert h is not None and h["Cookie"] == "session=abc"


def test_cookie_NOT_leaked_to_third_party() -> None:
    # This is the security-critical guarantee: creds never reach ip-api.com etc.
    assert _engine(cookie="session=abc")._auth_headers_for("ip-api.com") is None
    assert _engine(cookie="session=abc")._auth_headers_for("evil.com") is None


def test_auth_headers_scoped_too() -> None:
    eng = _engine(headers={"Authorization": "Bearer T"})
    assert eng._auth_headers_for("example.com") == {"Authorization": "Bearer T"}
    assert eng._auth_headers_for("cdn.other.com") is None


def test_no_auth_configured_returns_none() -> None:
    assert _engine()._auth_headers_for("example.com") is None


def test_parse_cookies_scopes_to_target() -> None:
    from types import SimpleNamespace

    from webrecon.modules.browser.module import _parse_cookies
    target = SimpleNamespace(hostname="example.com")
    cookies = _parse_cookies("a=1; b=2", target)
    assert cookies == [
        {"name": "a", "value": "1", "domain": "example.com", "path": "/"},
        {"name": "b", "value": "2", "domain": "example.com", "path": "/"},
    ]
    assert _parse_cookies(None, target) == []
