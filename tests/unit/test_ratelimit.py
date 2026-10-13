"""Unit: rate-limit / protection detection (passive headers + bounded active probe)."""

from __future__ import annotations

import asyncio
from dataclasses import dataclass

import pytest

from webrecon.core.config import ScanConfig
from webrecon.core.context import ScanContext
from webrecon.modules.ratelimit.analysis import (
    classify_probe,
    detect_protection,
    parse_rate_limit,
)
from webrecon.modules.ratelimit.module import MAX_PROBE_REQUESTS, RateLimitModule

# -- pure analysis --------------------------------------------------------------------


@pytest.mark.parametrize(("headers", "advertised", "policy_or_limit"), [
    ({"RateLimit-Limit": "100", "RateLimit-Remaining": "99"}, True, "100"),
    ({"X-RateLimit-Limit": "60"}, True, "60"),
    ({"RateLimit-Policy": "100;w=60"}, True, "100;w=60"),
    ({"Retry-After": "30"}, True, None),
    ({"Content-Type": "text/html"}, False, None),
    ({}, False, None),
])
def test_parse_rate_limit(headers, advertised, policy_or_limit) -> None:
    info = parse_rate_limit(headers)
    assert (info is not None) is advertised
    if advertised and policy_or_limit is not None:
        assert policy_or_limit in info.summary()


@pytest.mark.parametrize(("headers", "provider"), [
    ({"CF-RAY": "abc"}, "Cloudflare"),
    ({"Server": "cloudflare"}, "Cloudflare"),
    ({"x-sucuri-id": "1"}, "Sucuri"),
    ({"x-amzn-waf-action": "block"}, "AWS WAF"),
    ({"Server": "nginx"}, None),
    ({}, None),
])
def test_detect_protection(headers, provider) -> None:
    assert detect_protection(headers) == provider


@pytest.mark.parametrize(("statuses", "verdict", "tripped"), [
    ([200, 200, 429], "enforced", 3),
    ([429], "enforced", 1),
    ([200, 200, 200], "none_observed", None),
    ([200, 503, 503, 503], "blocked", None),
    ([200, 404, 200], "inconclusive", None),
    ([], "inconclusive", None),
])
def test_classify_probe(statuses, verdict, tripped) -> None:
    o = classify_probe(statuses)
    assert o.verdict == verdict
    assert o.tripped_at == tripped


# -- module behaviour -----------------------------------------------------------------


@dataclass
class _Resp:
    url: str
    status_code: int
    headers: dict


class _Http:
    """Fake HTTP engine returning a scripted status sequence."""

    def __init__(self, statuses, headers=None):
        self._statuses = list(statuses)
        self._headers = headers or {}
        self.calls = 0

    async def get(self, url, **kw):
        self.calls += 1
        status = self._statuses[min(self.calls - 1, len(self._statuses) - 1)]
        return _Resp(url, status, self._headers if status == 429 else {})


def _ctx(primary_headers, *, active=False, http=None):
    ctx = ScanContext(config=ScanConfig())
    ctx.config.active = active
    ctx.shared["primary_response"] = _Resp("https://ex.com/", 200, primary_headers)
    ctx.http = http

    class _T:
        base_url = "https://ex.com/"

    ctx.target = _T()
    return ctx


def _run(ctx):
    return asyncio.run(RateLimitModule().run(ctx))


def test_passive_reports_advertised_and_protection() -> None:
    r = _run(_ctx({"RateLimit-Limit": "100", "cf-ray": "x"}))
    checks = {f.check_id for f in r.findings}
    assert "ratelimit.advertised" in checks
    assert "ratelimit.protection.detected" in checks
    assert r.data["advertised"] is True and r.data["protection"] == "Cloudflare"


def test_passive_silent_when_no_signals() -> None:
    r = _run(_ctx({"Content-Type": "text/html"}))
    assert r.findings == [] and r.data["active_probe"] is None


def test_no_active_probe_without_active_flag() -> None:
    http = _Http([429])
    r = _run(_ctx({}, active=False, http=http))
    assert http.calls == 0 and r.data["active_probe"] is None


def test_active_probe_detects_enforcement() -> None:
    http = _Http([200, 200, 429], headers={"Retry-After": "5"})
    r = _run(_ctx({}, active=True, http=http))
    assert http.calls == 3  # stops at the first 429
    f = next(f for f in r.findings if f.check_id == "ratelimit.enforced")
    assert f.evidence[0].data["tripped_at"] == 3
    assert f.evidence[0].data["retry_after"] == "5"


def test_active_probe_flags_absent_rate_limiting() -> None:
    http = _Http([200])
    r = _run(_ctx({}, active=True, http=http))
    assert http.calls == MAX_PROBE_REQUESTS  # bounded, no early stop
    assert any(f.check_id == "ratelimit.absent" and f.severity.value == "low"
               for f in r.findings)


def test_active_probe_absent_suppressed_when_advertised() -> None:
    # If the server already advertises a quota, "no rate limiting" must not fire.
    http = _Http([200])
    r = _run(_ctx({"RateLimit-Limit": "100"}, active=True, http=http))
    assert not any(f.check_id == "ratelimit.absent" for f in r.findings)


def test_skips_without_primary_response() -> None:
    ctx = ScanContext(config=ScanConfig())
    r = _run(ctx)
    assert str(r.status) == "skipped"
