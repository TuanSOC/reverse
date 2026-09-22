"""Politeness controls: global + per-host rate limiting and concurrency (§34).

Conservative by default. A single shared limiter instance is threaded through
the HTTP engine so the whole scan respects one budget, and 429 responses can
trigger a cooperative slowdown.
"""

from __future__ import annotations

import asyncio
from collections import defaultdict
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager

from aiolimiter import AsyncLimiter

from ..core.config import RateLimitConfig


class RateLimiter:
    """Combines a token-bucket rate limit with concurrency semaphores."""

    def __init__(self, config: RateLimitConfig) -> None:
        self.config = config
        # AsyncLimiter(max_rate, time_period): allow N per second.
        rate = max(config.requests_per_second, 0.1)
        self._global_rate = AsyncLimiter(rate, 1.0)
        self._global_sem = asyncio.Semaphore(max(config.concurrency, 1))
        self._host_sems: dict[str, asyncio.Semaphore] = defaultdict(
            lambda: asyncio.Semaphore(max(config.per_host_concurrency, 1))
        )
        # Extra cooldown applied after a 429 (seconds), decays over time.
        self._penalty = 0.0
        self._lock = asyncio.Lock()

    @asynccontextmanager
    async def slot(self, host: str) -> AsyncIterator[None]:
        """Acquire a request slot for ``host`` respecting all limits."""
        host_sem = self._host_sems[host]
        async with self._global_sem, host_sem:
            await self._global_rate.acquire()
            penalty = self._penalty
            if penalty > 0:
                await asyncio.sleep(penalty)
            if self.config.request_delay_seconds > 0:
                await asyncio.sleep(self.config.request_delay_seconds)
            yield

    async def note_429(self) -> None:
        """Increase the cooldown after receiving HTTP 429 (§34)."""
        if not self.config.respect_429:
            return
        async with self._lock:
            self._penalty = min(self._penalty * 2 + 1.0, 30.0)

    async def note_success(self) -> None:
        """Decay the penalty after a successful request."""
        if self._penalty > 0:
            async with self._lock:
                self._penalty = max(self._penalty / 2.0, 0.0)
                if self._penalty < 0.05:
                    self._penalty = 0.0
