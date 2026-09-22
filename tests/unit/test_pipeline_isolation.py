"""A failing module must never crash the whole scan (§33)."""

from __future__ import annotations

from webrecon.core.config import ScanConfig
from webrecon.core.enums import ModuleStatus
from webrecon.core.module import ScannerModule
from webrecon.core.registry import ScannerRegistry
from webrecon.pipeline import Pipeline


class _BoomModule(ScannerModule):
    name = "boom"

    async def run(self, ctx):
        raise RuntimeError("intentional boom")


class _SlowModule(ScannerModule):
    name = "slow"
    timeout_seconds = 0.05

    async def run(self, ctx):
        import asyncio

        await asyncio.sleep(5)  # exceeds the 0.05s budget
        return self.new_result()


async def test_crashing_module_is_isolated() -> None:
    reg = ScannerRegistry()
    reg.register(_BoomModule)
    ctx = await Pipeline(ScanConfig(), registry=reg).run("http://127.0.0.1", selected=["boom"])
    assert ctx.results["boom"].status == ModuleStatus.FAILED
    assert "boom" in (ctx.results["boom"].error or "")


async def test_module_timeout_is_isolated() -> None:
    reg = ScannerRegistry()
    reg.register(_SlowModule)
    ctx = await Pipeline(ScanConfig(), registry=reg).run("http://127.0.0.1", selected=["slow"])
    assert ctx.results["slow"].status == ModuleStatus.TIMEOUT
    assert ctx.results["slow"].timed_out is True
