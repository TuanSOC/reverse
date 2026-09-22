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
from typing import TYPE_CHECKING, Any

from .config import ScanConfig
from .logging import get_logger
from .models import Finding, ModuleResult

if TYPE_CHECKING:  # pragma: no cover - typing only
    import structlog


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

    def __post_init__(self) -> None:
        if self.logger is None:
            self.logger = get_logger("scan", scan_id=self.scan_id)

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
