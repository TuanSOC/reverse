"""DNS-pinning backend closes the rebinding/TOCTOU window (§35, threat T1)."""

from __future__ import annotations

import ipaddress

import pytest

from webrecon.core.errors import SsrfBlockedError
from webrecon.engine.guarded_backend import GuardedBackend
from webrecon.engine.ssrf_guard import is_metadata


def test_is_metadata_unwraps_ipv4_mapped_ipv6() -> None:
    assert is_metadata(ipaddress.ip_address("169.254.169.254"))
    assert is_metadata(ipaddress.ip_address("::ffff:169.254.169.254"))
    assert not is_metadata(ipaddress.ip_address("93.184.216.34"))


async def test_backend_blocks_loopback_in_normal_mode() -> None:
    backend = GuardedBackend(allow_private=False)
    with pytest.raises(SsrfBlockedError, match="loopback"):
        await backend._pick_safe_ip("127.0.0.1", 80)


async def test_backend_blocks_localhost_resolution() -> None:
    # localhost resolves to loopback; the backend must reject it (rebinding path).
    backend = GuardedBackend(allow_private=False)
    with pytest.raises(SsrfBlockedError):
        await backend._pick_safe_ip("localhost", 80)


async def test_backend_lab_mode_allows_loopback_but_blocks_metadata() -> None:
    lab = GuardedBackend(allow_private=True)
    assert await lab._pick_safe_ip("127.0.0.1", 80) == "127.0.0.1"
    with pytest.raises(SsrfBlockedError, match="metadata"):
        await lab._pick_safe_ip("169.254.169.254", 80)


async def test_backend_allows_public_ip() -> None:
    backend = GuardedBackend(allow_private=False)
    assert await backend._pick_safe_ip("93.184.216.34", 80) == "93.184.216.34"
