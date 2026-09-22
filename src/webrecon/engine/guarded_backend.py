"""DNS-pinning network backend — closes the SSRF rebinding/TOCTOU window.

The request-level :class:`SsrfGuard` validates a hostname's resolved IPs, but if
the HTTP client then re-resolves the name when opening the socket, a
time-of-check/time-of-use gap remains: a TTL-0 attacker record can flip to
loopback/metadata between the check and the connect (classic DNS rebinding).

This backend removes the gap by making the *connect itself* the validation
point: it resolves the host, rejects unsafe addresses, and connects the socket
to a vetted IP. Because TLS SNI and certificate verification still use the
origin hostname (httpcore applies ``start_tls`` with the origin host, not the
connect address), HTTPS keeps working correctly.

It is installed into the httpx transport's connection pool (see
``HttpEngine.__aenter__``), so every connection — including every redirect hop —
is pinned.
"""

from __future__ import annotations

import asyncio
import socket

import httpcore

from ..core.errors import SsrfBlockedError
from .ssrf_guard import _as_ip, _classify_ip, is_metadata


class GuardedBackend(httpcore.AnyIOBackend):
    """A network backend that connects only to guard-validated IP addresses."""

    def __init__(self, *, allow_private: bool) -> None:
        self.allow_private = allow_private
        super().__init__()

    async def connect_tcp(
        self,
        host: str,
        port: int,
        timeout: float | None = None,  # noqa: ASYNC109 - signature dictated by httpcore
        local_address: str | None = None,
        socket_options=None,
    ):
        safe_ip = await self._pick_safe_ip(host, port)
        return await super().connect_tcp(
            safe_ip, port, timeout=timeout, local_address=local_address,
            socket_options=socket_options,
        )

    async def _pick_safe_ip(self, host: str, port: int) -> str:
        literal = _as_ip(host)
        if literal is not None:
            addresses = [str(literal)]
        else:
            loop = asyncio.get_running_loop()
            try:
                infos = await loop.getaddrinfo(host, port, proto=socket.IPPROTO_TCP)
            except socket.gaierror as exc:
                raise SsrfBlockedError(host, f"DNS resolution failed: {exc}") from exc
            addresses = list({str(i[4][0]) for i in infos})

        for addr in addresses:
            ip = _as_ip(addr)
            if ip is None:
                continue
            reason = _classify_ip(ip)
            if reason is None:
                return addr  # public and safe → connect here
            # Lab mode permits private/loopback but never the metadata endpoint.
            if self.allow_private and not is_metadata(ip):
                return addr
            raise SsrfBlockedError(host, f"{reason} ({addr}) [connect-time]")
        raise SsrfBlockedError(host, "no safe address resolved")
