"""Tool self-defense against hostile targets (§35, threats T1/T2/T7/T10)."""

from __future__ import annotations

import pytest

from webrecon.core.config import HttpConfig, RateLimitConfig, ScopeConfig, ScopeMode
from webrecon.core.errors import ScopeError, SsrfBlockedError
from webrecon.core.urls import parse_url
from webrecon.engine.http_engine import HttpEngine
from webrecon.engine.rate_limiter import RateLimiter
from webrecon.engine.scope_engine import ScopeEngine
from webrecon.engine.ssrf_guard import SsrfGuard


def _engine(mock_site: str, *, mode: ScopeMode = ScopeMode.SAME_ORIGIN) -> HttpEngine:
    p = parse_url(mock_site)
    scope = ScopeEngine(p.hostname, p.origin, ScopeConfig(mode=mode, allow_private_targets=True))
    return HttpEngine(
        HttpConfig(verify_tls=False),
        RateLimiter(RateLimitConfig(requests_per_second=100)),
        SsrfGuard(allow_private_targets=True),  # lab mode: still blocks metadata
        scope=scope,
    )


async def test_redirect_to_metadata_ip_is_refused(mock_site: str) -> None:
    # Even in lab mode, a redirect toward the cloud metadata IP is refused
    # (here the scope gate catches the off-host redirect first).
    async with _engine(mock_site) as http:
        with pytest.raises(ScopeError):  # SsrfBlockedError is also a ScopeError
            await http.get(mock_site + "/redirect-metadata")


async def test_ssrf_guard_blocks_metadata_even_when_scope_allows_it(mock_site: str) -> None:
    # Permit the metadata host in scope so the SSRF guard is the last line of defense.
    p = parse_url(mock_site)
    scope = ScopeEngine(
        p.hostname, p.origin,
        ScopeConfig(mode=ScopeMode.SAME_ORIGIN, allowed_hosts=["169.254.169.254"]),
    )
    engine = HttpEngine(
        HttpConfig(verify_tls=False),
        RateLimiter(RateLimitConfig(requests_per_second=100)),
        SsrfGuard(allow_private_targets=True),
        scope=scope,
    )
    async with engine as http:
        with pytest.raises(SsrfBlockedError):
            await http.get(mock_site + "/redirect-metadata")


async def test_weird_and_duplicate_headers_do_not_crash(mock_site: str) -> None:
    async with _engine(mock_site) as http:
        resp = await http.get(mock_site + "/weird-headers")
        assert resp.status_code == 200
        # Both Set-Cookie headers are preserved (not collapsed).
        assert len(resp.set_cookie) == 2


async def test_binary_body_decodes_without_raising(mock_site: str) -> None:
    async with _engine(mock_site) as http:
        resp = await http.get(mock_site + "/big")  # octet-stream
        _ = resp.text  # must not raise on non-text bytes
        assert isinstance(resp.text, str)


@pytest.mark.parametrize(
    "bad_url",
    [
        "file:///etc/passwd",
        "gopher://127.0.0.1:6379/_INFO",
        "http://[::1]/",  # IPv6 loopback
        "http://0.0.0.0/",
    ],
)
async def test_ssrf_guard_rejects_dangerous_urls(bad_url: str) -> None:
    guard = SsrfGuard()  # non-lab
    with pytest.raises(SsrfBlockedError):
        await guard.check_url(bad_url)


async def test_ssrf_guard_rechecks_resolved_ip_not_just_hostname() -> None:
    # A hostname that resolves to loopback must be blocked (rebinding defense).
    guard = SsrfGuard()
    with pytest.raises(SsrfBlockedError):
        # localhost resolves to 127.0.0.1 / ::1
        await guard.check_url("http://localhost/")
