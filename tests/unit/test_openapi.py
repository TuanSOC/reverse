"""Unit: OpenAPI 3.1 synthesis from endpoint rows."""

from __future__ import annotations

import pytest

from webrecon.intel.openapi import build_openapi, to_yaml


def _eps():
    return [
        {"url": "https://ex.com/api/users/{id}", "method": "GET", "kind": "rest",
         "observation": "observed",
         "meta": {"sources": ["javascript"], "discovery_status": "STATIC_AND_DYNAMIC",
                  "params": [
                      {"name": "id", "classification": "object_identifier", "source": "path"},
                      {"name": "page", "classification": "pagination", "source": "query"},
                      {"name": "X-Api-Key", "classification": "token", "source": "header"}]}},
        {"url": "https://ex.com/api/users/{id}", "method": "DELETE", "kind": "rest",
         "observation": "referenced", "meta": {"params": []}},
        {"url": "https://ex.com/api/login", "method": "POST", "kind": "rest",
         "observation": "observed",
         "meta": {"params": [{"name": "username", "classification": "user_identifier",
                              "source": "json"},
                             {"name": "password", "classification": "authentication",
                              "source": "json"}]}},
        {"url": "https://ex.com/graphql", "method": None, "kind": "graphql",
         "observation": "referenced", "meta": {}},
    ]


def test_document_shape() -> None:
    d = build_openapi(_eps(), target_url="https://ex.com/", title="My API", version="2.0")
    assert d["openapi"] == "3.1.0"
    assert d["info"]["title"] == "My API" and d["info"]["version"] == "2.0"
    assert d["servers"] == [{"url": "https://ex.com"}]
    assert set(d["paths"]) == {"/api/users/{id}", "/api/login"}  # graphql excluded
    assert set(d["paths"]["/api/users/{id}"]) == {"get", "delete"}


def test_parameter_locations_and_types() -> None:
    d = build_openapi(_eps(), target_url="https://ex.com/")
    params = {p["name"]: p for p in d["paths"]["/api/users/{id}"]["get"]["parameters"]}
    assert params["id"]["in"] == "path" and params["id"]["required"] is True
    assert params["page"]["in"] == "query" and params["page"]["schema"]["type"] == "integer"
    assert params["X-Api-Key"]["in"] == "header"


def test_json_body_from_body_params() -> None:
    d = build_openapi(_eps(), target_url="https://ex.com/")
    body = d["paths"]["/api/login"]["post"]["requestBody"]["content"]["application/json"]["schema"]
    assert body["type"] == "object"
    assert set(body["properties"]) == {"username", "password"}


def test_templated_path_gets_path_param_even_without_meta() -> None:
    d = build_openapi(_eps(), target_url="https://ex.com/")
    # the DELETE op has no param metadata, but {id} in the path must be declared
    ps = d["paths"]["/api/users/{id}"]["delete"]["parameters"]
    assert any(p["name"] == "id" and p["in"] == "path" for p in ps)


def test_provenance_and_tags() -> None:
    d = build_openapi(_eps(), target_url="https://ex.com/")
    op = d["paths"]["/api/users/{id}"]["get"]
    assert op["x-webrecon"]["observation"] == "observed"
    assert op["tags"] == ["api"]


def test_empty_and_no_target() -> None:
    d = build_openapi([], target_url=None)
    assert d["openapi"] == "3.1.0" and d["paths"] == {} and "servers" not in d
    assert d["info"]["title"].startswith("target")


def test_yaml_roundtrips() -> None:
    import yaml

    d = build_openapi(_eps(), target_url="https://ex.com/")
    loaded = yaml.safe_load(to_yaml(d))
    assert loaded["openapi"] == "3.1.0" and set(loaded["paths"]) == set(d["paths"])


@pytest.mark.parametrize("method", ["get", "Weird", None])
def test_unknown_method_defaults_to_get(method) -> None:
    d = build_openapi([{"url": "https://ex.com/x", "method": method, "kind": "rest",
                        "observation": "observed", "meta": {}}], target_url="https://ex.com/")
    assert "get" in d["paths"]["/x"]
