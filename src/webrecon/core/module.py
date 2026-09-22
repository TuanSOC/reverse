"""The single extension contract: a scanner module.

Adding a capability = writing one ``ScannerModule`` subclass and registering it
(§36). The pipeline resolves ``requires`` into a dependency order, enforces the
per-module ``timeout``, and wraps ``run`` so exceptions become a FAILED
``ModuleResult`` instead of crashing the scan.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import TYPE_CHECKING

from .models import ModuleResult

if TYPE_CHECKING:
    from .context import ScanContext


class ScannerModule(ABC):
    """Base class for all scanners.

    Subclasses set the class attributes and implement :meth:`run`. ``run`` must
    return a :class:`ModuleResult`; raising is tolerated (the pipeline records a
    failure) but returning a structured result is preferred so partial output is
    preserved.
    """

    #: Unique, stable identifier (used in config, storage, dependency graph).
    name: str = ""
    #: Semver-ish module version, surfaced in results and reports.
    version: str = "0.1.0"
    #: Names of modules whose output this one depends on.
    requires: tuple[str, ...] = ()
    #: Per-module execution budget in seconds; ``None`` uses the scan default.
    timeout_seconds: float | None = None
    #: Human-readable one-liner for docs/UI.
    description: str = ""

    def __init_subclass__(cls, **kwargs: object) -> None:
        super().__init_subclass__(**kwargs)
        # Enforce that concrete modules declare a name (abstract bases may not).
        if not getattr(cls, "__abstractmethods__", None) and not cls.name:
            raise TypeError(f"{cls.__name__} must define a non-empty `name`")

    def new_result(self) -> ModuleResult:
        """Create a result envelope pre-filled with this module's identity."""
        return ModuleResult(module=self.name, version=self.version)

    @abstractmethod
    async def run(self, ctx: ScanContext) -> ModuleResult:
        """Execute the module against the scan context and return a result."""
        raise NotImplementedError
