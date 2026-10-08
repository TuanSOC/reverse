"""Unit: report-intel review fixes — TLS/DNS from the live context, opt-in, no re-query."""

from __future__ import annotations

import asyncio

import pytest

from webrecon.core.config import ScanConfig
from webrecon.core.context import ScanContext
from webrecon.core.enums import ModuleStatus
from webrecon.core.models import ModuleResult, TargetInfo
from webrecon.intel.auth_flow import build_auth_flow
from webrecon.reporting import intel_sections
from webrecon.reporting.json_report import build_report


def _ctx() -> ScanContext:
    ctx = ScanContext(config=ScanConfig())
    ctx.target = TargetInfo(input_url="https://ex.com", scheme="https", hostname="ex.com",
                            port=443, base_url="https://ex.com", origin="https://ex.com")
    return ctx


def _result(module: str, status: ModuleStatus, data: dict) -> ModuleResult:
    r = ModuleResult(module=module)
    r.data = data
    r.mark_finished(status)
    return r


def _infra(intel: dict) -> list[str]:
    tree = intel["attack_surface"]
    grp = next((c for c in tree["children"] if c["id"] == "grp:infra"), None)
    return [c["type"] for c in grp["children"]] if grp else []


def test_skipped_tls_is_not_a_certificate() -> None:
    ctx = _ctx()
    ctx.results["tls"] = _result("tls", ModuleStatus.SKIPPED, {"skipped": "no TLS on ex.com:443"})
    assert "certificate" not in _infra(intel_sections.intel_from_ctx(ctx))
    ctx.results["tls"] = _result("tls", ModuleStatus.SUCCESS, {"subject": "CN=ex.com"})
    assert "certificate" in _infra(intel_sections.intel_from_ctx(ctx))


def test_live_dns_records_reach_the_attack_surface() -> None:
    ctx = _ctx()
    ctx.results["dns"] = _result("dns", ModuleStatus.SUCCESS,
                                 {"records": {"A": ["1.2.3.4"], "MX": ["mx.ex.com"]}})
    assert _infra(intel_sections.intel_from_ctx(ctx)).count("dns") == 2


def test_build_report_intel_is_optional_and_never_fatal(monkeypatch) -> None:
    ctx = _ctx()
    assert build_report(ctx, include_intel=False)["intelligence"] is None

    def boom(*a, **k):
        raise RuntimeError("bad data")

    monkeypatch.setattr(intel_sections, "intel_from_ctx", boom)
    rep = build_report(ctx)  # must not raise — scan results are still reported
    assert rep["intelligence"] is None and rep["scan_id"] == ctx.scan_id


def test_intel_from_db_reuses_preloaded_rows(monkeypatch) -> None:
    from webrecon.api import queries

    async def forbidden(*a, **k):
        raise AssertionError("re-queried a preloaded table")

    async def empty(*a, **k):
        return []

    async def none(*a, **k):
        return None

    for name in ("get_overview", "get_findings", "get_endpoints", "get_pages", "get_assets"):
        monkeypatch.setattr(queries, name, forbidden)
    for name in ("get_forms", "get_dns", "get_cookie_names"):
        monkeypatch.setattr(queries, name, empty)
    monkeypatch.setattr(queries, "get_certificates", empty)
    overview = {"target": {"hostname": "ex.com"}, "technologies": [], "ip_intel": None}
    intel = asyncio.run(intel_sections.intel_from_db(
        None, "sid", overview=overview, findings=[], endpoints=[], pages=[], assets=[]))
    assert intel["attack_surface"]["label"] == "ex.com"


@pytest.mark.parametrize(("endpoints", "form", "cookie", "keys"), [
    ([{"url": "https://ex.com/login"}, {"url": "https://ex.com/logout"}], True, True,
     ["form", "login", "session", "logout"]),
    ([{"url": "https://ex.com/oauth/authorize"}, {"url": "https://ex.com/callback"}],
     False, False, ["redirect", "authorize", "callback"]),
    ([], False, False, []),
])
def test_auth_steps_carry_stable_keys(endpoints, form, cookie, keys) -> None:
    flow = build_auth_flow(endpoints, has_login_form=form, has_session_cookie=cookie).to_dict()
    assert flow["step_keys"] == keys
    assert len(flow["steps"]) == len(flow["step_keys"])
