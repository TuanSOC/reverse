"""Attack-surface tree — a hierarchical view derived from the unified asset graph.

Pure (no I/O): takes the ``AssetGraph.to_dict()`` shape and folds it into a tree
the dashboard can render as a collapsible outline::

    domain
    ├── Web surface        host → path segments → page / endpoint (+ forms)
    ├── Static assets      grouped by asset type
    ├── Technologies
    └── Infrastructure     ip / dns / certificate

Findings hang off the node their evidence points at (``DERIVED_FROM`` edges) and
every node carries a severity rollup of its subtree, so the riskiest branch is
visible without expanding anything.
"""

from __future__ import annotations

from typing import Any
from urllib.parse import urlsplit

_SEV_RANK = {"critical": 4, "high": 3, "medium": 2, "low": 1, "informational": 0}
_INFRA_TYPES = ("ip", "dns", "certificate")
_MAX_PATH_DEPTH = 16


def _tnode(node_id: str, label: str, type_: str, props: dict | None = None) -> dict[str, Any]:
    return {"id": node_id, "label": label, "type": type_, "props": props or {},
            "children": [], "findings": [], "max_severity": None, "finding_count": 0}


def build_attack_surface(graph: dict[str, Any]) -> dict[str, Any]:
    """Fold a graph dict into an attack-surface tree (root = the target domain)."""
    nodes: dict[str, dict] = {n["id"]: n for n in graph.get("nodes", [])}
    domain = next((n for n in nodes.values() if n.get("type") == "domain"), None)
    if domain is None:
        return _tnode("root", "target", "domain")
    root = _tnode(domain["id"], domain.get("label") or domain["id"], "domain")
    index: dict[str, dict] = {domain["id"]: root}  # graph id -> tree node

    web = _tnode("grp:web", "Web surface", "group")
    assets = _tnode("grp:assets", "Static assets", "group")
    techs = _tnode("grp:tech", "Technologies", "group")
    infra = _tnode("grp:infra", "Infrastructure", "group")

    hosts: dict[str, dict] = {}
    path_nodes: dict[str, dict] = {}

    def _path_parent(url: str) -> tuple[dict, str]:
        """Return (parent tree node, leaf label) for a URL, creating path nodes."""
        try:
            parts = urlsplit(url)
        except ValueError:
            return web, url
        host = parts.hostname or "relative"
        if host not in hosts:
            hosts[host] = _tnode(f"host:{host}", host, "host")
            web["children"].append(hosts[host])
        parent = hosts[host]
        segs = [s for s in (parts.path or "/").split("/") if s]
        if len(segs) > _MAX_PATH_DEPTH:  # fold the tail into one leaf (bounded recursion)
            segs = segs[:_MAX_PATH_DEPTH] + ["/".join(segs[_MAX_PATH_DEPTH:])]
        prefix = ""
        for seg in segs[:-1]:
            prefix += "/" + seg
            key = f"{host}{prefix}"
            if key not in path_nodes:
                path_nodes[key] = _tnode(f"path:{key}", "/" + seg, "path")
                parent["children"].append(path_nodes[key])
            parent = path_nodes[key]
        leaf = "/" + (segs[-1] if segs else "")
        if parts.query:
            leaf += "?" + parts.query
        return parent, leaf

    for n in nodes.values():
        t = n.get("type")
        props = n.get("props") or {}
        if t in ("page", "endpoint"):
            url = n["id"].split(":", 1)[1] if ":" in n["id"] else n.get("label", "")
            parent, leaf = _path_parent(url)
            label = leaf
            if t == "endpoint" and props.get("method"):
                label = f"{props['method']} {leaf}"
            tn = _tnode(n["id"], label, t, {**props, "url": url})
            parent["children"].append(tn)
            index[n["id"]] = tn
        elif t == "asset":
            atype = props.get("type") or "other"
            grp_id = f"grp:assets:{atype}"
            grp = index.get(grp_id)
            if grp is None:
                grp = _tnode(grp_id, atype, "group")
                assets["children"].append(grp)
                index[grp_id] = grp
            tn = _tnode(n["id"], n.get("label") or n["id"], "asset", props)
            grp["children"].append(tn)
            index[n["id"]] = tn
        elif t == "technology":
            tn = _tnode(n["id"], n.get("label") or n["id"], t, props)
            techs["children"].append(tn)
            index[n["id"]] = tn
        elif t in _INFRA_TYPES:
            tn = _tnode(n["id"], n.get("label") or n["id"], t, props)
            infra["children"].append(tn)
            index[n["id"]] = tn

    # Second pass: forms under their page, findings onto their derived-from node.
    for e in graph.get("edges", []):
        src, dst, rel = e.get("source"), e.get("target"), e.get("relation")
        dnode = nodes.get(dst) or {}
        if rel == "CONTAINS" and dnode.get("type") == "form":
            parent = index.get(src, root)
            tn = _tnode(dst, dnode.get("label") or "form", "form", dnode.get("props") or {})
            parent["children"].append(tn)
            index[dst] = tn
        elif rel == "DERIVED_FROM" and dnode.get("type") == "finding":
            props = dnode.get("props") or {}
            index.get(src, root)["findings"].append({
                "id": dst, "label": dnode.get("label") or dst,
                "severity": props.get("severity"), "check_id": props.get("check_id"),
            })

    for grp in (web, assets, techs, infra):
        if grp["children"]:
            root["children"].append(grp)
    _rollup(root)
    return root


def _rollup(node: dict) -> tuple[int, int]:
    """Post-order: set ``max_severity`` + ``finding_count`` over each subtree."""
    best = max((_SEV_RANK.get(f.get("severity") or "", -1) for f in node["findings"]),
               default=-1)
    count = len(node["findings"])
    # Groups keep insertion order (stable sort); everything else is alphabetical.
    node["children"].sort(key=lambda c: (0, "") if c["type"] == "group" else (1, c["label"]))
    for child in node["children"]:
        c_best, c_count = _rollup(child)
        best = max(best, c_best)
        count += c_count
    node["finding_count"] = count
    node["max_severity"] = next((k for k, v in _SEV_RANK.items() if v == best), None)
    return best, count


def prune_findings(tree: dict[str, Any], keep) -> dict[str, Any]:
    """Copy of ``tree`` keeping only findings where ``keep(finding)``; rollups recomputed."""
    import copy

    out = copy.deepcopy(tree)

    def _walk(node: dict) -> None:
        node["findings"] = [f for f in node["findings"] if keep(f)]
        for c in node["children"]:
            _walk(c)

    _walk(out)
    _rollup(out)
    return out
