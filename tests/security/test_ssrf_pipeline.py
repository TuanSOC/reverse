"""Security: the pipeline must refuse unsafe targets without lab mode (T1)."""

from __future__ import annotations

import pytest

from webrecon.core.config import ScanConfig
from webrecon.core.enums import ModuleStatus
from webrecon.pipeline import Pipeline


@pytest.mark.parametrize(
    "url",
    [
        "http://127.0.0.1/",
        "http://169.254.169.254/latest/meta-data/",
        "http://10.0.0.1/",
        "http://192.168.0.1/",
        "http://localhost/",
    ],
)
async def test_unsafe_targets_are_blocked_by_default(url: str) -> None:
    cfg = ScanConfig()  # allow_private_targets defaults to False
    ctx = await Pipeline(cfg).run(url)
    target = ctx.results["target"]
    assert target.status == ModuleStatus.FAILED
    assert target.error
    # scope + http must be skipped because the target is invalid.
    assert ctx.results["scope"].status == ModuleStatus.SKIPPED
    assert ctx.results["http"].status == ModuleStatus.SKIPPED
    # No findings should be fabricated for a blocked target.
    assert ctx.target is None


async def test_non_http_scheme_blocked() -> None:
    ctx = await Pipeline(ScanConfig()).run("file:///etc/passwd")
    assert ctx.results["target"].status == ModuleStatus.FAILED
