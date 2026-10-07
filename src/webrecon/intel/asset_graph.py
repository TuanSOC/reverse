"""Unified asset graph — a typed, provenance-bearing view over stored scan data.

This is a *builder/view*, not a new persistence layer: it assembles typed nodes
(domain / ip / page / asset / endpoint / technology / dns / certificate / form /
finding) and relationships (HOSTED_ON / RESOLVES_TO / CONTAINS / REFERENCES /
CALLS / USES / PROTECTED_BY / DERIVED_FROM) from the existing SQLite tables, each
carrying source (discovery method), confidence, and evidence references — so the
UI, attack-surface tree, and AI layer all read one consistent model, and
backwards compatibility with the existing graph shape is preserved.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from ..api import queries
from ..storage.database import Database


@dataclass
class GraphNode:
    id: str
    label: str
    type: str
    source: str = ""            # discovery method
    confidence: float = 1.0
    props: dict[str, Any] = field(default_factory=dict)
    evidence_ids: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {"id": self.id, "label": self.label, "type": self.type,
                "source": self.source, "confidence": self.confidence,
                "props": self.props, "evidence_ids": self.evidence_ids}


@dataclass
class GraphEdge:
    source: str
    target: str
    relation: str
    confidence: float = 1.0

    def to_dict(self) -> dict[str, Any]:
        return {"source": self.source, "target": self.target,
                "relation": self.relation, "confidence": self.confidence}


@dataclass
class AssetGraph:
    nodes: list[GraphNode] = field(default_factory=list)
    edges: list[GraphEdge] = field(default_factory=list)
    _ids: set[str] = field(default_factory=set)

    def add_node(self, node: GraphNode) -> str:
        if node.id not in self._ids:
            self._ids.add(node.id)
            self.nodes.append(node)
        return node.id

    def add_edge(self, src: str, dst: str, relation: str, confidence: float = 1.0) -> None:
        if src in self._ids and dst in self._ids:
            self.edges.append(GraphEdge(src, dst, relation, confidence))

    def to_dict(self) -> dict[str, Any]:
        return {"nodes": [n.to_dict() for n in self.nodes],
                "edges": [e.to_dict() for e in self.edges]}


_MAX_PAGES = 60
_MAX_ASSETS = 60
_MAX_ENDPOINTS = 120


async def build_asset_graph(db: Database, scan_id: str) -> AssetGraph:
    """Assemble the unified asset graph for a scan from persisted entities."""
    g = AssetGraph()
    overview = await queries.get_overview(db, scan_id)
    if overview is None:
        return g
    host = (overview["target"] or {}).get("hostname") or "target"
    g.add_node(GraphNode(host, host, "domain", source="target"))

    # IP + network (ip_intel)
    ip = overview.get("ip_intel")
    if ip and ip.get("ips"):
        p = ip["ips"][0]
        if p.get("ip"):
            ipid = g.add_node(GraphNode(
                f"ip:{p['ip']}", p["ip"], "ip", source="ip_intel", confidence=0.9,
                props={"asn": p.get("asn"), "provider": p.get("provider"),
                       "country": p.get("country"), "edge_cdn": ip.get("edge_cdn")}))
            g.add_edge(host, ipid, "HOSTED_ON", 0.9)

    # Technologies
    for t in overview.get("technologies", []):
        tid = g.add_node(GraphNode(
            f"tech:{t['name']}", f"{t['name']} {t.get('version') or ''}".strip(),
            "technology", source="technology", confidence=_conf(t.get("confidence")),
            props={"category": t.get("category"), "version": t.get("version")}))
        g.add_edge(host, tid, "USES", _conf(t.get("confidence")))

    # DNS + certificate
    for d in await queries.get_dns(db, scan_id):
        did = g.add_node(GraphNode(
            f"dns:{d['record_type']}:{d['value']}",
            f"{d['record_type']} {d['value']}", "dns", source="dns"))
        g.add_edge(host, did, "RESOLVES_TO")
    if await queries.get_certificates(db, scan_id):
        cid = g.add_node(GraphNode("cert", "TLS certificate", "certificate", source="tls"))
        g.add_edge(host, cid, "PROTECTED_BY")

    # Pages + forms
    page_ids: dict[str, str] = {}
    for pg in (await queries.get_pages(db, scan_id))[:_MAX_PAGES]:
        url = pg.get("url") or ""
        if not url:
            continue
        pid = g.add_node(GraphNode(f"page:{url}", _short(url, host), "page",
                                   source="crawler", props={"status": pg.get("status_code")}))
        page_ids[url] = pid
        g.add_edge(host, pid, "CONTAINS")
    for fm in await queries.get_forms(db, scan_id):
        page_url = fm.get("page_url") or ""
        fid = g.add_node(GraphNode(
            f"form:{fm.get('action') or page_url}", f"form {fm.get('method', 'get')}",
            "form", source="crawler", props={"action": fm.get("action")}))
        g.add_edge(page_ids.get(page_url, host), fid, "CONTAINS")

    # Static assets (scripts etc.)
    for a in (await queries.get_assets(db, scan_id))[:_MAX_ASSETS]:
        url = a.get("url") or ""
        if not url:
            continue
        aid = g.add_node(GraphNode(f"asset:{url}", _short(url, host), "asset",
                                   source="crawler", props={"type": a.get("type")}))
        g.add_edge(host, aid, "REFERENCES")

    # Endpoints (with method / discovery status / params)
    for e in (await queries.get_endpoints(db, scan_id))[:_MAX_ENDPOINTS]:
        url = e.get("url") or ""
        if not url:
            continue
        meta = e.get("meta") or {}
        eid = g.add_node(GraphNode(
            f"ep:{url}", url, "endpoint", source=(e.get("source") or "api"),
            confidence=_obs_conf(e.get("observation")),
            props={"method": e.get("method"), "observation": e.get("observation"),
                   "discovery_status": meta.get("discovery_status"),
                   "params": meta.get("params", [])}))
        g.add_edge(host, eid, "CALLS" if e.get("method") else "REFERENCES",
                   _obs_conf(e.get("observation")))

    # Findings linked to the asset their evidence points at (else to host)
    for f in await queries.get_findings(db, scan_id):
        fid = g.add_node(GraphNode(
            f"finding:{f['id']}", f.get("name") or f.get("check_id") or "finding",
            "finding", source=f.get("module") or "security",
            confidence=_conf(f.get("confidence")),
            props={"severity": f.get("severity"), "check_id": f.get("check_id")},
            evidence_ids=[str(f["id"])]))
        target = _finding_target(f, g._ids, host)
        g.add_edge(target, fid, "DERIVED_FROM", _conf(f.get("confidence")))

    return g


def _finding_target(finding: dict, ids: set[str], host: str) -> str:
    for ev in finding.get("evidence", []) or []:
        url = ev.get("url")
        if url:
            for prefix in ("ep:", "asset:", "page:"):
                if f"{prefix}{url}" in ids:
                    return f"{prefix}{url}"
    return host


def _short(url: str, host: str) -> str:
    try:
        from urllib.parse import urlsplit
        p = urlsplit(url)
        return (p.path or "/") + (("?" + p.query) if p.query else "")
    except ValueError:
        return url[:60]


def _conf(level: str | None) -> float:
    return {"confirmed": 1.0, "high": 0.9, "medium": 0.6, "low": 0.4,
            "informational": 0.3}.get(str(level or "").lower(), 0.5)


def _obs_conf(obs: str | None) -> float:
    return {"observed": 0.95, "referenced": 0.6, "potential": 0.4}.get(
        str(obs or "").lower(), 0.5)
