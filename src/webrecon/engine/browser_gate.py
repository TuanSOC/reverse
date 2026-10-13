"""Request gate for headless-browser pages (browser module + auto-login).

``page.route`` only intercepts the *first* request of a redirect chain — the
browser follows 3xx hops internally without consulting the handler (also after
``route.fulfill`` with a 3xx, verified against Chromium). So the gate follows
the chain itself: every hop is fetched with redirects disabled and checked
(scheme, scope, SSRF guard) before the next one is requested; the final
response is fulfilled to the page. Trade-off: the page keeps the original URL.
"""

from __future__ import annotations

from collections.abc import Awaitable, Callable
from typing import Any
from urllib.parse import urljoin

from ..core.errors import SsrfBlockedError
from .ssrf_guard import SsrfGuard

_PASSTHROUGH = ("data", "blob", "about")
MAX_REDIRECTS = 10


def make_route_gate(
    guard: SsrfGuard,
    allowed: Callable[[str], bool] | None = None,
    *,
    on_block: Callable[[str, str], None] | None = None,
) -> Callable[[Any], Awaitable[None]]:
    """Build a ``page.route("**/*", gate)`` handler.

    ``allowed`` is an extra policy (e.g. the scope engine); ``on_block`` is told
    ``(url, reason)`` for every aborted request.
    """

    async def _block(route: Any, url: str, reason: str) -> None:
        if on_block is not None:
            on_block(url, reason)
        await route.abort()

    async def _refusal(url: str) -> str | None:
        """Why ``url`` must not be requested, or ``None`` if it may."""
        scheme = url.split(":", 1)[0].lower()
        if scheme not in ("http", "https"):
            return "scheme"
        if allowed is not None and not allowed(url):
            return "out of scope"
        try:
            await guard.check_url(url)
        except SsrfBlockedError as exc:
            return f"ssrf: {exc.reason}"
        except Exception:  # noqa: BLE001 - unresolvable etc.: fail closed
            return "unresolvable"
        return None

    async def _gate(route: Any) -> None:
        url = route.request.url
        if url.split(":", 1)[0].lower() in _PASSTHROUGH:
            await route.continue_()  # never leaves the browser
            return
        if (reason := await _refusal(url)) is not None:
            await _block(route, url, reason)
            return
        method = route.request.method
        try:
            response = await route.fetch(max_redirects=0)
            for _ in range(MAX_REDIRECTS):
                location = response.headers.get("location")
                if not (300 <= response.status < 400 and location):
                    break
                nxt = urljoin(url, location)
                if (reason := await _refusal(nxt)) is not None:
                    await _block(route, nxt, f"redirect: {reason}")
                    return
                if response.status == 303 or (response.status in (301, 302)
                                              and method == "POST"):
                    method = "GET"  # browser semantics for redirected POSTs
                url = nxt
                response = await route.fetch(url=url, method=method, max_redirects=0)
            else:
                await _block(route, url, "too many redirects")
                return
        except Exception:  # noqa: BLE001 - network error → let the page see a failure
            await route.abort()
            return
        await route.fulfill(response=response)

    return _gate
