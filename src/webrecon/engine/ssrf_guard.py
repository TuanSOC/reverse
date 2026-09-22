"""SSRF guard — the tool's hard safety boundary (§3/§35, threat T1).

Every URL that is about to be fetched passes through here first. The guard:

1. rejects non-http(s) schemes (``file://``, ``gopher://``, …);
2. resolves the hostname to its actual IP addresses;
3. rejects any address that is loopback / private / link-local / reserved /
   multicast / unspecified, or the cloud metadata IP (169.254.169.254).

Because it checks the *resolved* IPs (not just the hostname string), it defeats
DNS-based tricks like ``localtest.me`` → 127.0.0.1 and rebinding. Lab/local
testing requires explicitly setting ``allow_private_targets=True`` (§3).

The guard performs **no** requests — only name resolution — so it cannot itself
be an SSRF vector.
"""

from __future__ import annotations

import asyncio
import ipaddress
import socket
from dataclasses import dataclass
from urllib.parse import urlsplit

from ..core.errors import SsrfBlockedError

ALLOWED_SCHEMES = frozenset({"http", "https"})

# Cloud metadata endpoints that must never be reachable via the tool.
_METADATA_IPS = frozenset({"169.254.169.254", "fd00:ec2::254"})

# Hostnames we refuse outright regardless of resolution.
_BLOCKED_HOSTNAMES = frozenset({"localhost", "localhost.localdomain", "ip6-localhost"})


@dataclass(frozen=True)
class ResolvedTarget:
    """Result of a successful guard check."""

    hostname: str
    port: int
    addresses: tuple[str, ...]


def is_metadata(ip: ipaddress.IPv4Address | ipaddress.IPv6Address) -> bool:
    """True if ``ip`` is a cloud metadata endpoint (unwrapping IPv4-mapped IPv6)."""
    if str(ip) in _METADATA_IPS:
        return True
    mapped = getattr(ip, "ipv4_mapped", None)
    return mapped is not None and str(mapped) in _METADATA_IPS


def _classify_ip(ip: ipaddress.IPv4Address | ipaddress.IPv6Address) -> str | None:
    """Return a rejection reason for an unsafe IP, or ``None`` if it is public."""
    if is_metadata(ip):
        return "cloud metadata address"
    if ip.is_loopback:
        return "loopback address"
    if ip.is_private:
        return "private address"
    if ip.is_link_local:
        return "link-local address"
    if ip.is_multicast:
        return "multicast address"
    if ip.is_reserved:
        return "reserved address"
    if ip.is_unspecified:
        return "unspecified address"
    # IPv4-mapped IPv6 (e.g. ::ffff:127.0.0.1) — unwrap and re-check.
    mapped = getattr(ip, "ipv4_mapped", None)
    if mapped is not None:
        return _classify_ip(mapped)
    return None


async def _resolve(hostname: str, port: int) -> list[str]:
    """Resolve a hostname to a list of IP strings (async, via a thread)."""
    loop = asyncio.get_running_loop()
    try:
        infos = await loop.getaddrinfo(hostname, port, proto=socket.IPPROTO_TCP)
    except socket.gaierror as exc:
        raise SsrfBlockedError(hostname, f"DNS resolution failed: {exc}") from exc
    return list({str(info[4][0]) for info in infos})


class SsrfGuard:
    """Validates targets before any network access."""

    def __init__(self, *, allow_private_targets: bool = False) -> None:
        self.allow_private_targets = allow_private_targets

    def check_scheme(self, url: str) -> str:
        """Validate the scheme and return the hostname, or raise."""
        parts = urlsplit(url)
        if parts.scheme.lower() not in ALLOWED_SCHEMES:
            raise SsrfBlockedError(url, f"scheme {parts.scheme!r} not allowed")
        if not parts.hostname:
            raise SsrfBlockedError(url, "missing hostname")
        return parts.hostname

    async def check_url(self, url: str) -> ResolvedTarget:
        """Full check: scheme + resolution + IP classification. Raises on block."""
        parts = urlsplit(url)
        scheme = parts.scheme.lower()
        if scheme not in ALLOWED_SCHEMES:
            raise SsrfBlockedError(url, f"scheme {scheme!r} not allowed")
        hostname = parts.hostname
        if not hostname:
            raise SsrfBlockedError(url, "missing hostname")
        port = parts.port or (443 if scheme == "https" else 80)

        if self.allow_private_targets:
            # Lab mode: skip private-address rejection but still resolve so a
            # dead host fails fast. Metadata IPs stay blocked even in lab mode.
            addrs = await self._safe_resolve(hostname, port)
            for a in addrs:
                ip = _as_ip(a)
                if ip is not None and is_metadata(ip):
                    raise SsrfBlockedError(url, "cloud metadata address (blocked even in lab mode)")
            return ResolvedTarget(hostname, port, tuple(addrs))

        if hostname.lower() in _BLOCKED_HOSTNAMES:
            raise SsrfBlockedError(url, "blocked hostname")

        # A bare IP literal is classified directly (no resolution needed).
        literal = _as_ip(hostname)
        if literal is not None:
            reason = _classify_ip(literal)
            if reason:
                raise SsrfBlockedError(url, reason)
            return ResolvedTarget(hostname, port, (str(literal),))

        addrs = await _resolve(hostname, port)
        if not addrs:
            raise SsrfBlockedError(url, "no addresses resolved")
        for a in addrs:
            ip = _as_ip(a)
            if ip is None:
                raise SsrfBlockedError(url, f"unparseable address {a!r}")
            reason = _classify_ip(ip)
            if reason:
                raise SsrfBlockedError(url, f"{reason} ({a})")
        return ResolvedTarget(hostname, port, tuple(addrs))

    async def _safe_resolve(self, hostname: str, port: int) -> list[str]:
        literal = _as_ip(hostname)
        if literal is not None:
            return [str(literal)]
        return await _resolve(hostname, port)


def _as_ip(value: str) -> ipaddress.IPv4Address | ipaddress.IPv6Address | None:
    try:
        return ipaddress.ip_address(value)
    except ValueError:
        return None
