"""The scan context threaded through every module.

Modules read shared configuration, the target, and prior modules' results from
here, and write their own outputs back. It also carries the cooperative
cancellation token (§29) and shared inventories. Engine/scope/storage handles
are attached by the pipeline in later phases; they are optional so core and unit
tests can construct a context without the network stack.
"""

from __future__ import annotations

import asyncio
import uuid
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import TYPE_CHECKING, Any

from .config import ScanConfig
from .logging import get_logger
from .models import Finding, ModuleResult

if TYPE_CHECKING:  # pragma: no cover - typing only
    import structlog

#: Hard cap on timeline events kept per scan; further events are counted, not stored.
MAX_SCAN_EVENTS = 5000


@dataclass
class ScanEvent:
    """One timeline entry: something was discovered / observed / found (G6).

    ``data`` must stay small and must never carry secret values — callers pass
    identifiers (URLs, check ids, counts), not response bodies.
    """

    seq: int
    ts: datetime
    kind: str          # scan | module | auth | discovered | observed | finding
    label: str
    module: str | None = None
    data: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {"seq": self.seq, "ts": self.ts.isoformat(), "kind": self.kind,
                "label": self.label, "module": self.module, "data": self.data}


class CancellationToken:
    """Cooperative cancellation (§29/§33). Modules poll :meth:`raise_if_cancelled`."""

    def __init__(self) -> None:
        self._event = asyncio.Event()

    def cancel(self) -> None:
        self._event.set()

    @property
    def cancelled(self) -> bool:
        return self._event.is_set()

    def raise_if_cancelled(self) -> None:
        if self._event.is_set():
            from .errors import ScanCancelledError

            raise ScanCancelledError("scan cancelled")

    async def wait(self) -> None:
        await self._event.wait()


@dataclass
class ScanContext:
    """Mutable per-scan state shared across modules."""

    config: ScanConfig
    scan_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    #: Populated by the target module in Phase 2.
    target: Any = None
    #: Engine/scope/storage handles attached by the pipeline (Phase 2+).
    scope: Any = None
    http: Any = None
    storage: Any = None
    cancellation: CancellationToken = field(default_factory=CancellationToken)
    #: Results keyed by module name, so a module can read upstream output.
    results: dict[str, ModuleResult] = field(default_factory=dict)
    #: Free-form shared bag for cross-module data (asset inventory, etc.).
    shared: dict[str, Any] = field(default_factory=dict)
    logger: structlog.stdlib.BoundLogger | None = None
    #: Ordered scan timeline (G6); the pipeline persists it incrementally.
    events: list[ScanEvent] = field(default_factory=list)
    #: Events dropped after :data:`MAX_SCAN_EVENTS` was reached.
    events_dropped: int = 0
    #: Module currently running — set by the pipeline, used to attribute events.
    current_module: str | None = None

    def __post_init__(self) -> None:
        if self.logger is None:
            self.logger = get_logger("scan", scan_id=self.scan_id)

    # -- timeline -------------------------------------------------------------

    def event(self, kind: str, label: str, data: dict[str, Any] | None = None) -> None:
        """Record a timeline event, attributed to the running module.

        Never raises and never blocks: once the cap is hit, events are only
        counted so a huge site cannot balloon memory or the database.
        """
        if len(self.events) >= MAX_SCAN_EVENTS:
            self.events_dropped += 1
            return
        self.events.append(ScanEvent(
            seq=len(self.events), ts=datetime.now(UTC), kind=kind, label=label,
            module=self.current_module, data=dict(data or {}),
        ))

    # -- convenience accessors ---------------------------------------------

    def result_of(self, module: str) -> ModuleResult | None:
        return self.results.get(module)

    def all_findings(self) -> list[Finding]:
        out: list[Finding] = []
        for res in self.results.values():
            out.extend(res.findings)
        return out

    def bind_logger(self, module: str) -> structlog.stdlib.BoundLogger:
        return get_logger(module, scan_id=self.scan_id)
