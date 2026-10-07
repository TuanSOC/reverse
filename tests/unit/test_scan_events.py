"""Unit: the ScanContext timeline sink (G6)."""

from __future__ import annotations

from webrecon.core import context as context_mod
from webrecon.core.config import ScanConfig
from webrecon.core.context import ScanContext


def test_event_is_ordered_and_attributed_to_running_module() -> None:
    ctx = ScanContext(config=ScanConfig())
    ctx.event("scan", "started")
    ctx.current_module = "crawler"
    ctx.event("observed", "Page 200: /", {"entity": "page", "url": "/"})
    ctx.current_module = None

    assert [e.seq for e in ctx.events] == [0, 1]
    assert ctx.events[0].module is None
    assert ctx.events[1].module == "crawler"
    d = ctx.events[1].to_dict()
    assert d["kind"] == "observed" and d["data"]["entity"] == "page"
    assert isinstance(d["ts"], str) and "T" in d["ts"]


def test_event_data_is_copied_not_aliased() -> None:
    ctx = ScanContext(config=ScanConfig())
    payload = {"url": "/a"}
    ctx.event("discovered", "x", payload)
    payload["url"] = "/mutated"
    assert ctx.events[0].data["url"] == "/a"


def test_event_cap_counts_drops(monkeypatch) -> None:
    monkeypatch.setattr(context_mod, "MAX_SCAN_EVENTS", 3)
    ctx = ScanContext(config=ScanConfig())
    for i in range(5):
        ctx.event("discovered", f"e{i}")
    assert len(ctx.events) == 3
    assert ctx.events_dropped == 2
