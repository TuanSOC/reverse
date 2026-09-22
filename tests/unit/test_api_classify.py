"""Endpoint aggregation + classification (§19)."""

from __future__ import annotations

from webrecon.core.enums import Observation
from webrecon.modules.api.classify import EndpointAggregator, looks_like_api


def test_looks_like_api() -> None:
    assert looks_like_api("https://ex.com/api/v1/users")
    assert looks_like_api("/graphql")
    assert looks_like_api("/admin/panel")
    assert not looks_like_api("/about")
    assert not looks_like_api("/images/logo.png")


def test_observation_never_downgrades_and_dedups() -> None:
    agg = EndpointAggregator("ex.com")
    agg.add("https://ex.com/api/users", Observation.REFERENCED, "javascript")
    agg.add("https://ex.com/api/users", Observation.OBSERVED, "crawler")
    agg.add("https://ex.com/api/users", Observation.REFERENCED, "sitemap")
    eps = agg.endpoints()
    assert len(eps) == 1
    assert eps[0].observation == Observation.OBSERVED  # strongest wins
    assert eps[0].sources == {"javascript", "crawler", "sitemap"}


def test_kind_detection() -> None:
    agg = EndpointAggregator("ex.com")
    agg.add("wss://ex.com/socket", Observation.REFERENCED, "javascript")
    agg.add("https://ex.com/graphql", Observation.REFERENCED, "javascript")
    agg.add("https://ex.com/api/x", Observation.REFERENCED, "javascript")
    kinds = {e.kind for e in agg.endpoints()}
    assert kinds == {"websocket", "graphql", "rest"}


def test_scope_flagging() -> None:
    agg = EndpointAggregator("ex.com")
    agg.add("https://ex.com/api/x", Observation.REFERENCED, "js")
    agg.add("https://third.com/api/y", Observation.REFERENCED, "js")
    by_url = {e.url.split("//")[1].split("/")[0]: e for e in agg.endpoints()}
    assert by_url["ex.com"].in_scope
    assert not by_url["third.com"].in_scope


def test_sensitive_flag() -> None:
    agg = EndpointAggregator("ex.com")
    agg.add("https://ex.com/api/admin/settings", Observation.REFERENCED, "js")
    assert agg.endpoints()[0].sensitive


def test_captures_query_param_names() -> None:
    agg = EndpointAggregator("ex.com")
    agg.add("https://ex.com/api/search?q=1&page=2", Observation.OBSERVED, "crawler")
    agg.add("https://ex.com/api/search?sort=asc", Observation.REFERENCED, "js")
    ep = agg.endpoints()[0]
    assert ep.url == "https://ex.com/api/search"  # query stripped from the key
    assert ep.params == {"q", "page", "sort"}  # but param names retained


def test_no_params_when_none() -> None:
    agg = EndpointAggregator("ex.com")
    agg.add("https://ex.com/api/users", Observation.OBSERVED, "crawler")
    assert agg.endpoints()[0].params == set()
