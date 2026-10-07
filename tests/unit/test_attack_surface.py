"""Unit: attack-surface tree derived from an asset-graph dict."""

from __future__ import annotations

from webrecon.intel.attack_surface import build_attack_surface


def _graph() -> dict:
    nodes = [
        {"id": "ex.com", "label": "ex.com", "type": "domain", "props": {}},
        {"id": "ep:https://ex.com/api/users/{id}", "label": "x", "type": "endpoint",
         "props": {"method": "GET", "observation": "observed"}},
        {"id": "ep:https://ex.com/api/login", "label": "x", "type": "endpoint",
         "props": {"method": "POST"}},
        {"id": "page:https://ex.com/account?tab=1", "label": "x", "type": "page", "props": {}},
        {"id": "form:/login", "label": "form post", "type": "form", "props": {}},
        {"id": "asset:https://ex.com/app.js", "label": "/app.js", "type": "asset",
         "props": {"type": "script"}},
        {"id": "tech:nginx", "label": "nginx", "type": "technology", "props": {}},
        {"id": "ip:1.2.3.4", "label": "1.2.3.4", "type": "ip", "props": {}},
        {"id": "finding:f1", "label": "IDOR candidate", "type": "finding",
         "props": {"severity": "high", "check_id": "api.idor"}},
        {"id": "finding:f2", "label": "Missing HSTS", "type": "finding",
         "props": {"severity": "low", "check_id": "headers.hsts"}},
    ]
    edges = [
        {"source": "page:https://ex.com/account?tab=1", "target": "form:/login",
         "relation": "CONTAINS"},
        {"source": "ep:https://ex.com/api/users/{id}", "target": "finding:f1",
         "relation": "DERIVED_FROM"},
        {"source": "ex.com", "target": "finding:f2", "relation": "DERIVED_FROM"},
    ]
    return {"nodes": nodes, "edges": edges}


def _find(node: dict, node_id: str) -> dict | None:
    if node["id"] == node_id:
        return node
    for c in node["children"]:
        hit = _find(c, node_id)
        if hit:
            return hit
    return None


def test_tree_groups_and_path_hierarchy() -> None:
    tree = build_attack_surface(_graph())
    assert tree["type"] == "domain" and tree["label"] == "ex.com"
    # groups in a fixed, meaningful order
    assert [c["label"] for c in tree["children"]] == [
        "Web surface", "Static assets", "Technologies", "Infrastructure"]
    api = _find(tree, "path:ex.com/api")
    assert api is not None and api["label"] == "/api"
    users = _find(tree, "path:ex.com/api/users")
    leaf = _find(tree, "ep:https://ex.com/api/users/{id}")
    assert users is not None and leaf in users["children"]
    assert leaf["label"] == "GET /{id}"
    login = _find(tree, "ep:https://ex.com/api/login")
    assert login is not None and login in api["children"]


def test_forms_nest_under_page_and_query_kept() -> None:
    tree = build_attack_surface(_graph())
    page = _find(tree, "page:https://ex.com/account?tab=1")
    assert page["label"] == "/account?tab=1"
    assert [c["type"] for c in page["children"]] == ["form"]


def test_findings_attach_and_severity_rolls_up() -> None:
    tree = build_attack_surface(_graph())
    leaf = _find(tree, "ep:https://ex.com/api/users/{id}")
    assert [f["check_id"] for f in leaf["findings"]] == ["api.idor"]
    # rollup: the /api branch inherits the endpoint's high finding
    assert _find(tree, "path:ex.com/api")["max_severity"] == "high"
    assert _find(tree, "grp:tech")["max_severity"] is None
    # root sees both findings: its own low + the high below
    assert tree["finding_count"] == 2 and tree["max_severity"] == "high"


def test_asset_type_groups() -> None:
    tree = build_attack_surface(_graph())
    grp = _find(tree, "grp:assets:script")
    assert grp is not None and grp["children"][0]["type"] == "asset"


def test_empty_graph_yields_bare_root() -> None:
    tree = build_attack_surface({"nodes": [], "edges": []})
    assert tree["children"] == [] and tree["finding_count"] == 0
