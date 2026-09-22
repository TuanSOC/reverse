"""Scope engine boundary logic (§4)."""

from __future__ import annotations

from webrecon.core.config import ScopeConfig, ScopeMode
from webrecon.engine.scope_engine import ScopeEngine


def _engine(mode: ScopeMode, **kw) -> ScopeEngine:
    cfg = ScopeConfig(mode=mode, **kw)
    return ScopeEngine("example.com", "https://example.com:443", cfg)


def test_same_domain_allows_subdomains_and_blocks_others() -> None:
    e = _engine(ScopeMode.SAME_DOMAIN)
    assert e.is_allowed("https://example.com/")
    assert e.is_allowed("https://www.example.com/x")
    assert e.is_allowed("https://api.example.com/x")
    assert not e.is_allowed("https://google.com/")
    assert not e.is_allowed("https://facebook.com/")


def test_same_origin_blocks_other_scheme_or_port() -> None:
    e = _engine(ScopeMode.SAME_ORIGIN)
    assert e.is_allowed("https://example.com/")
    assert not e.is_allowed("https://example.com:8443/")
    assert not e.is_allowed("https://www.example.com/")


def test_include_subdomains() -> None:
    e = _engine(ScopeMode.INCLUDE_SUBDOMAINS)
    assert e.is_allowed("https://deep.sub.example.com/")
    assert not e.is_allowed("https://example.org/")


def test_disallowed_host_takes_precedence() -> None:
    e = _engine(ScopeMode.SAME_DOMAIN, disallowed_hosts=["secret.example.com"])
    assert not e.is_allowed("https://secret.example.com/")
    assert e.is_allowed("https://public.example.com/")


def test_allowed_host_overrides_mode() -> None:
    e = _engine(ScopeMode.SAME_ORIGIN, allowed_hosts=["cdn.other.com"])
    assert e.is_allowed("https://cdn.other.com/asset.js")


def test_path_include_exclude() -> None:
    e = _engine(ScopeMode.SAME_DOMAIN, exclude_paths=["/admin"])
    assert not e.is_allowed("https://example.com/admin/panel")
    assert e.is_allowed("https://example.com/public")

    e2 = _engine(ScopeMode.SAME_DOMAIN, include_paths=["/app"])
    assert e2.is_allowed("https://example.com/app/x")
    assert not e2.is_allowed("https://example.com/other")


def test_reason_is_reported() -> None:
    e = _engine(ScopeMode.SAME_DOMAIN)
    decision = e.evaluate("https://google.com/")
    assert not decision.allowed
    assert decision.reason
