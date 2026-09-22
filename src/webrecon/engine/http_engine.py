"""The single shared HTTP engine (§5).

All network access in WebRecon goes through here, so safety and politeness are
enforced in exactly one place:

* **SSRF guard on every hop.** Redirects are followed *manually* (auto-redirects
  disabled) so each hop's resolved IP is re-checked — a 30x to an internal
  address is blocked (threat T1).
* **Scope gate.** If a :class:`ScopeEngine` is attached, out-of-scope URLs are
  refused before the request is sent (§4).
* **Response-size cap.** The body is read incrementally and aborted past
  ``max_response_bytes`` to stop decompression/huge-response bombs (threat T2).
* **Rate limiting + retry.** Conservative limits, exponential backoff, 429 slow-down.

The engine records nothing to the DB itself; it returns structured
:class:`HttpResponse` objects and lets modules decide what to persist.
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field

import httpx

from ..core.config import HttpConfig
from ..core.errors import ScopeError, SsrfBlockedError, WebReconError
from ..core.logging import get_logger
from ..core.urls import parse_url
from .rate_limiter import RateLimiter
from .scope_engine import ScopeEngine
from .ssrf_guard import SsrfGuard

log = get_logger("http")


@dataclass
class RedirectHop:
    url: str
    status_code: int
    location: str | None


@dataclass
class HttpResponse:
    """Structured result of a request (after following redirects safely)."""

    url: str  # final URL
    requested_url: str
    method: str
    status_code: int
    headers: dict[str, str]
    content_type: str | None
    content_length: int | None
    elapsed_ms: float
    body: bytes
    truncated: bool
    # Raw multi-valued Set-Cookie headers (a plain dict would collapse them).
    set_cookie: list[str] = field(default_factory=list)
    redirect_chain: list[RedirectHop] = field(default_factory=list)

    @property
    def text(self) -> str:
        # Defensive decode; never raises on hostile bytes.
        return self.body.decode("utf-8", errors="replace")


class HttpEngineError(WebReconError):
    """Raised for non-security transport failures (timeout, connection)."""


class HttpEngine:
    """Async HTTP client wrapper. Use as an async context manager."""

    def __init__(
        self,
        config: HttpConfig,
        rate_limiter: RateLimiter,
        ssrf_guard: SsrfGuard,
        scope: ScopeEngine | None = None,
    ) -> None:
        self.config = config
        self.rate = rate_limiter
        self.guard = ssrf_guard
        self.scope = scope
        self._client: httpx.AsyncClient | None = None

    async def __aenter__(self) -> HttpEngine:
        self._client = httpx.AsyncClient(
            follow_redirects=False,  # we follow manually to guard each hop
            timeout=httpx.Timeout(self.config.timeout_seconds),
            headers={"User-Agent": self.config.user_agent},
            verify=self.config.verify_tls,
            max_redirects=0,
        )
        return self

    async def __aexit__(self, *exc: object) -> None:
        if self._client is not None:
            await self._client.aclose()
            self._client = None

    async def request(self, method: str, url: str) -> HttpResponse:
        """Perform a guarded, scope-checked, size-capped request."""
        if self._client is None:
            raise HttpEngineError("HttpEngine used outside its context manager")

        if self.scope is not None and not self.scope.is_allowed(url):
            decision = self.scope.evaluate(url)
            raise ScopeError(f"out of scope: {url} ({decision.reason})")

        requested_url = url
        chain: list[RedirectHop] = []
        current = url
        started = time.perf_counter()

        for _ in range(self.config.max_redirects + 1):
            # SSRF check BEFORE each hop (also re-checks after redirects).
            await self.guard.check_url(current)
            host = parse_url(current).hostname
            resp = await self._send_with_retry(method, host, current)

            if resp.is_redirect and self.config.follow_redirects:
                location = resp.headers.get("location")
                chain.append(RedirectHop(current, resp.status_code, location))
                await resp.aclose()
                if not location:
                    break
                nxt = str(resp.url.join(location))
                # Redirect target must also pass the scope gate.
                if self.scope is not None and not self.scope.is_allowed(nxt):
                    raise ScopeError(f"redirect out of scope: {nxt}")
                current = nxt
                continue

            body, truncated = await self._read_capped(resp)
            elapsed = (time.perf_counter() - started) * 1000.0
            set_cookie = resp.headers.get_list("set-cookie")
            await resp.aclose()
            return HttpResponse(
                url=str(resp.url),
                requested_url=requested_url,
                method=method.upper(),
                status_code=resp.status_code,
                headers=dict(resp.headers),
                content_type=resp.headers.get("content-type"),
                content_length=_int_or_none(resp.headers.get("content-length")),
                elapsed_ms=elapsed,
                body=body,
                truncated=truncated,
                set_cookie=list(set_cookie),
                redirect_chain=chain,
            )

        raise HttpEngineError(f"too many redirects for {requested_url}")

    async def get(self, url: str) -> HttpResponse:
        return await self.request("GET", url)

    async def head(self, url: str) -> HttpResponse:
        return await self.request("HEAD", url)

    async def _send_with_retry(self, method: str, host: str, url: str) -> httpx.Response:
        if self._client is None:  # pragma: no cover - guarded by request()
            raise HttpEngineError("HttpEngine used outside its context manager")
        attempts = self.config_retries + 1
        last_exc: Exception | None = None
        for attempt in range(attempts):
            async with self.rate.slot(host):
                try:
                    req = self._client.build_request(method, url)
                    resp = await self._client.send(req, stream=True)
                except (httpx.ConnectError, httpx.ReadError, httpx.WriteError) as exc:
                    last_exc = exc
                    await self._backoff(attempt)
                    continue
                except httpx.TimeoutException as exc:
                    last_exc = exc
                    await self._backoff(attempt)
                    continue
            if resp.status_code == 429:
                await self.rate.note_429()
                await resp.aclose()
                last_exc = HttpEngineError("429 Too Many Requests")
                await self._backoff(attempt)
                continue
            if resp.status_code >= 500 and attempt < attempts - 1:
                await resp.aclose()
                await self._backoff(attempt)
                continue
            await self.rate.note_success()
            return resp
        raise HttpEngineError(f"request failed after {attempts} attempts: {last_exc}")

    @property
    def config_retries(self) -> int:
        return self.rate.config.max_retries

    async def _backoff(self, attempt: int) -> None:
        import asyncio

        base = self.rate.config.backoff_base_seconds
        await asyncio.sleep(min(base * (2**attempt), 15.0))

    async def _read_capped(self, resp: httpx.Response) -> tuple[bytes, bool]:
        """Read the body up to the configured cap; abort past it (threat T2)."""
        cap = self.config.max_response_bytes
        chunks: list[bytes] = []
        total = 0
        truncated = False
        async for chunk in resp.aiter_bytes():
            total += len(chunk)
            if total > cap:
                # Keep only up to the cap, flag truncation, stop reading.
                remaining = cap - (total - len(chunk))
                if remaining > 0:
                    chunks.append(chunk[:remaining])
                truncated = True
                log.warning("response truncated at cap", url=str(resp.url), cap=cap)
                break
            chunks.append(chunk)
        return b"".join(chunks), truncated


def _int_or_none(value: str | None) -> int | None:
    if value is None:
        return None
    try:
        return int(value)
    except ValueError:
        return None


__all__ = ["HttpEngine", "HttpResponse", "RedirectHop", "HttpEngineError", "SsrfBlockedError"]
