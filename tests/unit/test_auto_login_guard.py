"""Unit: auto-login safety — login host policy, SSRF refusal, cookie scoping, field pick."""

from __future__ import annotations

import asyncio

import pytest

from webrecon.core.config import ScanConfig
from webrecon.core.context import ScanContext
from webrecon.engine.auto_login import cookies_to_header, login_host_allowed, rank_login_fields
from webrecon.pipeline import Pipeline


@pytest.mark.parametrize(("login", "target", "ok"), [
    ("example.com", "example.com", True),
    ("sso.example.com", "example.com", True),        # child of target
    ("example.com", "app.example.com", True),        # parent of target
    ("SSO.Example.com.", "example.com", True),       # case + trailing dot normalized
    ("localhost", "localhost", True),                # single-label lab hosts
    ("juice-shop", "juice-shop", True),
    ("127.0.0.1", "127.0.0.1", True),
    # siblings are refused: without a public-suffix list they can be other tenants
    ("sso.example.com", "app.example.com", False),
    ("attacker.herokuapp.com", "myapp.herokuapp.com", False),
    ("x.github.io", "me.github.io", False),
    ("evil.co.uk", "example.co.uk", False),
    ("evil.co.uk", "shop.example.co.uk", False),
    # IP literals: exact match only
    ("1.8.8.8", "8.8.8.8", False),
    ("192.0.0.5", "10.0.0.5", False),
    ("attacker.tld", "example.com", False),
    ("example.com.attacker.tld", "example.com", False),
    ("", "example.com", False),
])
def test_login_host_allowed(login: str, target: str, ok: bool) -> None:
    assert login_host_allowed(login, target) is ok


def _run_auto_login(login_url: str, monkeypatch, *, allow_private: bool = False,
                    target: str = "https://example.com/"):
    called = []

    async def fake_capture(cfg, host, log):  # must never run for refused URLs
        called.append(host)
        return "session=abc"

    monkeypatch.setattr("webrecon.engine.auto_login.capture_session_cookies", fake_capture)
    cfg = ScanConfig()
    cfg.scope.allow_private_targets = allow_private
    cfg.auth.login_url = login_url
    cfg.auth.username = "u"
    cfg.auth.password = "p"
    ctx = ScanContext(config=cfg)
    asyncio.run(Pipeline(cfg)._auto_login(ctx, target))
    return called, ctx, cfg


@pytest.mark.parametrize("login_url", [
    "http://169.254.169.254/latest/meta-data/",     # SSRF guard (metadata IP)
    "http://127.0.0.1:8080/admin",                  # loopback, lab mode off
    "https://attacker.tld/login",                   # off-site credential theft
])
def test_refused_login_url_never_launches_browser(login_url: str, monkeypatch) -> None:
    called, ctx, cfg = _run_auto_login(login_url, monkeypatch)
    assert called == []
    assert cfg.http.cookie is None
    ev = [e for e in ctx.events if e.kind == "auth"]
    assert ev and ev[-1].data["authenticated"] is False and ev[-1].data.get("reason")


def test_ssrf_guard_applies_even_on_same_host(monkeypatch) -> None:
    # Auto-login runs before the target module, so it must not reach loopback
    # unless lab mode is on — even when the login page is on the target host.
    called, ctx, _ = _run_auto_login("http://127.0.0.1:8000/login", monkeypatch,
                                     target="http://127.0.0.1:8000/")
    assert called == []
    assert "SSRF" in ctx.events[-1].data["reason"]
    called, _, _ = _run_auto_login("http://127.0.0.1:8000/login", monkeypatch,
                                   target="http://127.0.0.1:8000/", allow_private=True)
    assert called == ["127.0.0.1"]


def test_same_site_login_url_is_used(monkeypatch) -> None:
    async def fake_check(self, url):  # avoid real DNS for example.com
        return None

    monkeypatch.setattr("webrecon.engine.ssrf_guard.SsrfGuard.check_url", fake_check)
    called, ctx, cfg = _run_auto_login("https://sso.example.com/login", monkeypatch)
    assert called == ["example.com"]
    assert cfg.http.cookie == "session=abc"


def test_child_domain_cookie_not_sent_to_parent() -> None:
    cookies = [
        {"name": "a", "value": "1", "domain": "example.com"},
        {"name": "b", "value": "2", "domain": ".example.com"},
        {"name": "c", "value": "3", "domain": "sso.example.com"},   # child: drop
        {"name": "d", "value": "4", "domain": "other.com"},
    ]
    assert cookies_to_header(cookies, "example.com") == "a=1; b=2"
    # a host inside the cookie domain still receives the parent-domain cookies
    assert cookies_to_header(cookies, "sso.example.com") == "a=1; b=2; c=3"


def test_hinted_username_at_index_zero_wins() -> None:
    inputs = [
        {"type": "email", "name": "email"},
        {"type": "text", "name": "captcha"},
        {"type": "password", "name": "pw"},
    ]
    f = rank_login_fields(inputs)
    assert (f.username_index, f.password_index) == (0, 2)
