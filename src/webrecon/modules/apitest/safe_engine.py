"""GET-only engine wrapper — structural enforcement of the safety contract.

The apitest module must never issue a non-idempotent request. Rather than trust
call-site discipline, every apitest request goes through :class:`SafeGetEngine`,
which physically refuses any method other than GET. A unit test asserts the
refusal, turning "we tested one path" into an invariant (red-team #3).
"""

from __future__ import annotations

from ...engine.http_engine import HttpEngine, HttpResponse


class UnsafeMethodError(RuntimeError):
    """Raised when apitest attempts anything other than a GET request."""


class SafeGetEngine:
    """Wraps the shared HttpEngine and permits GET only."""

    def __init__(self, engine: HttpEngine) -> None:
        self._engine = engine

    async def get(self, url: str) -> HttpResponse:
        return await self._engine.get(url)

    async def request(self, method: str, url: str) -> HttpResponse:
        if method.upper() != "GET":
            raise UnsafeMethodError(
                f"apitest is GET-only; refused method {method!r} for {url}"
            )
        return await self._engine.get(url)
