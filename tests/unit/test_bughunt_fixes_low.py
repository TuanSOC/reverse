"""Unit: lower-severity bug-hunt fixes (DNS, robots, forms, AI/report plumbing, timestamps)."""

from __future__ import annotations

import asyncio

import dns.exception
import dns.resolver
import pytest

from webrecon.api.queries import _iso, filter_report_min_severity
from webrecon.intel.attack_surface import build_attack_surface, prune_findings
from webrecon.modules.active_verify.analysis import REDIRECT_VARIANTS, build_redirect_probe
from webrecon.modules.crawler.models import DiscoveredForm
from webrecon.modules.crawler.robots import parse_robots
from webrecon.modules.dns.analysis import resolve_state
from webrecon.modules.forms_auth.module import _distinct_forms
from webrecon.modules.javascript.analysis import analyze_js

# -- DNS: only NXDOMAIN means the name is gone ---------------------------------------


class _Resolver:
    def __init__(self, behaviour):
        self.behaviour = behaviour

    async def resolve(self, name, rtype):
        b = self.behaviour.get(rtype, self.behaviour.get("*"))
        if isinstance(b, Exception):
            raise b
        return b


@pytest.mark.parametrize(("behaviour", "state"), [
    ({"*": dns.resolver.NXDOMAIN()}, "nxdomain"),
    ({"*": dns.exception.Timeout()}, "unknown"),          # was counted as dangling
    ({"*": dns.resolver.NoNameservers()}, "unknown"),     # SERVFAIL
    ({"A": ["1.2.3.4"]}, "resolves"),
    ({"*": dns.resolver.NoAnswer()}, "resolves"),          # name exists, no A/AAAA/CNAME
])
def test_resolve_state(behaviour, state) -> None:
    assert asyncio.run(resolve_state(_Resolver(behaviour), "x.example")) == state


# -- robots: consecutive User-agent lines form one group ------------------------------


def test_robots_consecutive_user_agents_share_rules() -> None:
    txt = ("User-agent: Googlebot\nUser-agent: *\nDisallow: /private\n\n"
           "User-agent: Bing\nDisallow: /b\n")
    rules = parse_robots(txt, user_agent="WebRecon")
    assert rules.disallow == ["/private"]


# -- forms: a site-wide form is one form ------------------------------------------------


def test_site_wide_form_deduplicated() -> None:
    inputs = [{"name": "q", "type": "text"}]
    forms = [DiscoveredForm(page_url=f"https://ex.com/p{i}", action="https://ex.com/search",
                            method="post", inputs=inputs) for i in range(5)]
    forms.append(DiscoveredForm(page_url="https://ex.com/a", action=None, method="post",
                                inputs=inputs))
    forms.append(DiscoveredForm(page_url="https://ex.com/b", action=None, method="post",
                                inputs=inputs))
    assert len(_distinct_forms(forms)) == 3  # 1 shared action + 2 self-posting pages


# -- active_verify: the double-encoded variant is really double-encoded -----------------


def test_double_encoded_redirect_payload_on_the_wire() -> None:
    payload = dict(REDIRECT_VARIANTS)["double_encoded"]
    url = build_redirect_probe("https://ex.com/r?next=x", "next", payload)
    assert "%252f%252f" in url and "%25252f" not in url


# -- javascript: documentation example keys are not secrets ----------------------------


def test_js_ignores_aws_documentation_key() -> None:
    a = analyze_js("https://ex.com/a.js", 'var k="AKIAIOSFODNN7EXAMPLE";')
    assert a.secrets == []


# -- API plumbing ---------------------------------------------------------------------


def test_iso_timestamps_carry_utc_offset() -> None:
    from datetime import UTC, datetime

    assert _iso(datetime(2026, 10, 8, 9, 0)).endswith("+00:00")
    assert _iso(datetime(2026, 10, 8, 9, 0, tzinfo=UTC)).endswith("+00:00")
    assert _iso(None) is None


def test_min_severity_prunes_attack_surface_counts() -> None:
    graph = {"nodes": [
        {"id": "ex.com", "label": "ex.com", "type": "domain"},
        {"id": "finding:h", "label": "H", "type": "finding", "props": {"severity": "high"}},
        {"id": "finding:l", "label": "L", "type": "finding", "props": {"severity": "low"}},
    ], "edges": [{"source": "ex.com", "target": "finding:h", "relation": "DERIVED_FROM"},
                 {"source": "ex.com", "target": "finding:l", "relation": "DERIVED_FROM"}]}
    tree = build_attack_surface(graph)
    rep = {"findings": [{"severity": "high"}, {"severity": "low"}], "summary": {},
           "intelligence": {"attack_surface": tree}}
    out = filter_report_min_severity(rep, "high")
    assert out["intelligence"]["attack_surface"]["finding_count"] == 1
    assert tree["finding_count"] == 2  # the original is untouched
    assert prune_findings(tree, lambda f: False)["max_severity"] is None
