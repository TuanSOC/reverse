"""HTTP engine against the local mock site (§5/§6, threats T1/T2/T8)."""

from __future__ import annotations

import pytest

from webrecon.core.config import HttpConfig, RateLimitConfig, ScopeConfig, ScopeMode
from webrecon.core.errors import ScopeError, SsrfBlockedError
from webrecon.core.urls import parse_url
from webrecon.engine.http_engine import HttpEngine
from webrecon.engine.rate_limiter import RateLimiter
from webrecon.engine.scope_engine import ScopeEngine
from webrecon.engine.ssrf_guard import SsrfGuard


def _engine(mock_site: str, *, max_bytes: int = 10 * 1024 * 1024) -> HttpEngine:
    p = parse_url(mock_site)
    scope = ScopeEngine(p.hostname, p.origin, ScopeConfig(mode=ScopeMode.SAME_ORIGIN))
    return HttpEngine(
        HttpConfig(max_response_bytes=max_bytes, verify_tls=False),
        RateLimiter(RateLimitConfig(requests_per_second=50)),
        SsrfGuard(allow_private_targets=True),
        scope=scope,
    )


async def test_get_ok(mock_site: str) -> None:
    async with _engine(mock_site) as http:
        resp = await http.get(mock_site + "/")
        assert resp.status_code == 200
        assert "Mock Site" in resp.text
        assert resp.content_type and resp.content_type.startswith("text/html")


async def test_follows_internal_redirect(mock_site: str) -> None:
    async with _engine(mock_site) as http:
        resp = await http.get(mock_site + "/redirect")
        assert resp.status_code == 200
        assert len(resp.redirect_chain) == 1
        assert resp.redirect_chain[0].status_code == 301


async def test_out_of_scope_redirect_is_blocked(mock_site: str) -> None:
    async with _engine(mock_site) as http:
        with pytest.raises(ScopeError):
            await http.get(mock_site + "/redirect-external")


async def test_response_size_cap_truncates(mock_site: str) -> None:
    async with _engine(mock_site, max_bytes=1024) as http:
        resp = await http.get(mock_site + "/big")
        assert resp.truncated is True
        assert len(resp.body) <= 1024


async def test_ssrf_guard_blocks_metadata_even_via_engine() -> None:
    scope = ScopeEngine("169.254.169.254", "http://169.254.169.254:80", ScopeConfig())
    eng = HttpEngine(
        HttpConfig(),
        RateLimiter(RateLimitConfig()),
        SsrfGuard(allow_private_targets=True),
        scope=scope,
    )
    async with eng as http:
        with pytest.raises(SsrfBlockedError):
            await http.get("http://169.254.169.254/latest/meta-data/")
