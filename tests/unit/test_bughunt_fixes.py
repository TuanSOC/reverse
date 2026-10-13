"""Unit: regressions for the codebase-wide bug hunt (pipeline/api/cli/modules/intel)."""

from __future__ import annotations

import asyncio

import pytest

from webrecon.core.config import ScanConfig
from webrecon.core.context import ScanContext
from webrecon.core.enums import ModuleStatus
from webrecon.core.models import ModuleResult
from webrecon.core.module import ScannerModule
from webrecon.core.registry import ScannerRegistry
from webrecon.core.urls import registrable_domain
from webrecon.intel.ai import parse_analysis
from webrecon.intel.ai.context import AnalysisContext, EvidenceItem
from webrecon.intel.attack_surface import build_attack_surface
from webrecon.modules.active_verify.analysis import effective_redirect_host
from webrecon.modules.apitest.signatures import is_introspection_result
from webrecon.modules.technology.fingerprint import _is_library_file, fingerprint
from webrecon.pipeline import Pipeline

# -- pipeline: cancellation is reported as such ------------------------------------


def test_cancelled_scan_status_is_cancelled() -> None:
    reg = ScannerRegistry()
    ran: list[str] = []

    @reg.register
    class A(ScannerModule):
        name = "a"

        async def run(self, ctx):  # type: ignore[override]
            ran.append("a")
            ctx.cancellation.cancel()  # user hits Cancel while "a" runs
            r = self.new_result()
            r.mark_finished(ModuleStatus.SUCCESS)
            return r

    @reg.register
    class B(ScannerModule):
        name = "b"
        requires = ("a",)

        async def run(self, ctx):  # type: ignore[override]
            ran.append("b")
            return self.new_result()

    ctx = asyncio.run(Pipeline(ScanConfig(), registry=reg).run("http://127.0.0.1/"))
    assert ran == ["a"]
    assert ctx.shared["overall_status"] == "cancelled"


def test_scan_events_and_logs_hide_url_credentials() -> None:
    reg = ScannerRegistry()
    ctx = asyncio.run(Pipeline(ScanConfig(), registry=reg).run(
        "http://admin:hunter2@ex.com/?api_key=SECRET"))
    started = ctx.events[0]
    assert "hunter2" not in started.label and "SECRET" not in started.label
    assert started.data["url"] == "http://ex.com/?api_key=*"


# -- API manager ------------------------------------------------------------------------


def test_manager_cancelled_scan_skips_ai_and_reports_cancelled(monkeypatch) -> None:
    from webrecon.api.app import _SimpleManager
    from webrecon.core.context import CancellationToken

    mgr = _SimpleManager(db=None)  # type: ignore[arg-type]
    q = mgr.subscribe("sid")
    ai_calls: list = []

    async def fake_analyze(*a, **k):
        ai_calls.append(1)

    monkeypatch.setattr("webrecon.intel.ai.analyze_scan", fake_analyze)

    class _Pipe:
        async def run(self, url, **kw):
            c = ScanContext(config=ScanConfig())
            c.shared["overall_status"] = "cancelled"
            return c

    mgr.status["sid"] = "running"
    asyncio.run(mgr._run(_Pipe(), "http://x", "sid", CancellationToken(), "stub"))
    assert mgr.status["sid"] == "cancelled"
    assert q.get_nowait() == {"module": "_done", "status": "cancelled", "index": 0, "total": 0}
    assert ai_calls == []
    assert mgr.cancel("sid") is False  # finished scans can't be cancelled


# -- CLI summary ------------------------------------------------------------------------


def test_cli_summary_survives_markup_in_finding_names(capsys) -> None:
    from webrecon.cli.app import _print_summary

    _print_summary({
        "scan_id": "abcd", "target": {"base_url": "http://[/x]"},
        "summary": {"total_findings": 1, "by_severity": {"low": 1}},
        "findings": [{"severity": "low", "confidence": "high", "observation": "observed",
                      "check_id": "cookie.[/x]", "name": "Cookie '[/x]' missing Secure"}],
    })
    assert "[/x]" in capsys.readouterr().out


# -- AI parsing -------------------------------------------------------------------------


@pytest.mark.parametrize("bad", [1, True, 3.5, {"x": 1}])
def test_parse_analysis_non_list_evidence_is_rejected_not_crash(bad) -> None:
    ctx = AnalysisContext("s", "https://ex.com", [EvidenceItem("X1", "target", "t")])
    a = parse_analysis({"app_summary": {"text": "hi", "evidence": bad},
                        "components": [{"text": "c", "evidence": bad}]},
                       ctx, provider="t", model="m")
    assert a.app_summary is None and a.sections["components"] == []
    assert a.rejected_claims == 2


# -- modules ----------------------------------------------------------------------------


@pytest.mark.parametrize(("host", "expected"), [
    ("203.0.113.10", "203.0.113.10"), ("[2001:db8::1]", "2001:db8::1"),
    ("www.example.co.uk", "example.co.uk"), ("a.b.example.com", "example.com"),
])
def test_registrable_domain_ip_literals(host: str, expected: str) -> None:
    assert registrable_domain(host) == expected


@pytest.mark.parametrize(("location", "host"), [
    ("https://canary.example/", "canary.example"),
    ("//canary.example/x", "canary.example"),
    ("/\\canary.example", "canary.example"),
    ("/login?next=https%3A%2F%2Fcanary.example%2F", None),   # relative bounce — not off-site
    ("/home", None),
])
def test_open_redirect_only_leading_scheme_counts(location: str, host) -> None:
    assert effective_redirect_host(location) == host


@pytest.mark.parametrize("body", ['{"data":"x"}', '{"data":[1]}', '{"data":null}', "[]", "x"])
def test_odd_graphql_bodies_are_not_introspection(body: str) -> None:
    assert is_introspection_result(body) is False
    assert is_introspection_result('{"data":{"__schema":{"types":[]}}}') is True


def test_library_url_version_fallback() -> None:
    assert _is_library_file("jQuery", "https://x/js/jquery-3.7.1.min.js")
    assert _is_library_file("jQuery", "https://x/jquery.min.js?ver=3.6.0")
    assert not _is_library_file("jQuery", "https://x/jquery.validate-1.19.5.min.js")
    assert not _is_library_file("WordPress", "https://x/wp-content/plugins/p/app.js?ver=5.9.3")


def test_fingerprint_ignores_plugin_versions() -> None:
    dets = fingerprint(headers={}, cookies=[], html="", meta_generator=None, script_urls=[
        "https://x/js/jquery.validate-1.19.5.min.js", "https://x/js/jquery-3.7.1.min.js"])
    jq = next((d for d in dets if d.name.lower() == "jquery"), None)
    assert jq is not None and jq.version == "3.7.1"


def test_attack_surface_survives_very_deep_paths() -> None:
    deep = "http://ex.com" + "/a" * 999
    graph = {"nodes": [{"id": "ex.com", "label": "ex.com", "type": "domain"},
                       {"id": f"ep:{deep}", "label": deep, "type": "endpoint", "props": {}}],
             "edges": []}
    tree = build_attack_surface(graph)  # used to raise RecursionError
    assert tree["type"] == "domain"


def test_module_result_type_still_constructible() -> None:
    assert ModuleResult(module="x").module == "x"
