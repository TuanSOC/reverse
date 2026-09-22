"""Registry + dependency ordering (§36)."""

from __future__ import annotations

import pytest

from webrecon.core.context import ScanContext
from webrecon.core.errors import ConfigError
from webrecon.core.module import ScannerModule
from webrecon.core.registry import ScannerRegistry


def _mod(name_: str, requires_: tuple[str, ...] = ()) -> type[ScannerModule]:
    class _M(ScannerModule):
        name = name_
        requires = requires_

        async def run(self, ctx: ScanContext):  # noqa: D401
            return self.new_result()

    return _M


def test_register_and_order_respects_dependencies() -> None:
    reg = ScannerRegistry()
    reg.register(_mod("target"))
    reg.register(_mod("scope", ("target",)))
    reg.register(_mod("http", ("scope",)))
    order = reg.resolution_order()
    assert order.index("target") < order.index("scope") < order.index("http")


def test_selected_pulls_transitive_deps() -> None:
    reg = ScannerRegistry()
    reg.register(_mod("target"))
    reg.register(_mod("scope", ("target",)))
    reg.register(_mod("tls", ("target",)))
    order = reg.resolution_order(selected=["scope"])
    assert set(order) == {"target", "scope"}
    assert order.index("target") < order.index("scope")


def test_cycle_is_rejected() -> None:
    reg = ScannerRegistry()
    reg.register(_mod("a", ("b",)))
    reg.register(_mod("b", ("a",)))
    with pytest.raises(ConfigError, match="cycle"):
        reg.resolution_order()


def test_unknown_dependency_rejected() -> None:
    reg = ScannerRegistry()
    reg.register(_mod("a", ("ghost",)))
    with pytest.raises(ConfigError, match="unknown"):
        reg.resolution_order()


def test_duplicate_name_rejected() -> None:
    reg = ScannerRegistry()
    reg.register(_mod("dup"))
    with pytest.raises(ConfigError, match="duplicate"):
        reg.register(_mod("dup"))


def test_concrete_module_without_name_is_rejected() -> None:
    with pytest.raises(TypeError, match="name"):

        class _Bad(ScannerModule):
            async def run(self, ctx: ScanContext):
                return self.new_result()
