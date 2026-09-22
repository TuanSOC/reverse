"""SSRF guard — the hard safety boundary (§3/§35, threat T1)."""

from __future__ import annotations

import pytest

from webrecon.core.errors import SsrfBlockedError
from webrecon.engine.ssrf_guard import SsrfGuard


async def test_rejects_non_http_scheme() -> None:
    guard = SsrfGuard()
    with pytest.raises(SsrfBlockedError):
        await guard.check_url("file:///etc/passwd")
    with pytest.raises(SsrfBlockedError):
        await guard.check_url("gopher://example.com")


async def test_blocks_loopback_ip_literal() -> None:
    guard = SsrfGuard()
    with pytest.raises(SsrfBlockedError, match="loopback"):
        await guard.check_url("http://127.0.0.1/")


async def test_blocks_private_ip_literal() -> None:
    guard = SsrfGuard()
    for ip in ("http://10.0.0.5/", "http://192.168.1.1/", "http://172.16.0.1/"):
        with pytest.raises(SsrfBlockedError, match="private"):
            await guard.check_url(ip)


async def test_blocks_metadata_ip() -> None:
    guard = SsrfGuard()
    with pytest.raises(SsrfBlockedError, match="metadata"):
        await guard.check_url("http://169.254.169.254/latest/meta-data/")


async def test_blocks_localhost_hostname() -> None:
    guard = SsrfGuard()
    with pytest.raises(SsrfBlockedError):
        await guard.check_url("http://localhost:8080/")


async def test_allows_public_ip_literal() -> None:
    guard = SsrfGuard()
    resolved = await guard.check_url("http://93.184.216.34/")  # example.com's IP range
    assert "93.184.216.34" in resolved.addresses


async def test_lab_mode_allows_loopback_but_not_metadata() -> None:
    guard = SsrfGuard(allow_private_targets=True)
    resolved = await guard.check_url("http://127.0.0.1:9/")
    assert resolved.hostname == "127.0.0.1"
    with pytest.raises(SsrfBlockedError, match="metadata"):
        await guard.check_url("http://169.254.169.254/")
