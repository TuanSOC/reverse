"""Intelligence sections for reports: attack surface, API endpoints, parameters, auth flow.

One pure builder (:func:`build_intel_sections`) fed from either source:

* a stored scan (:func:`intel_from_db`) — ``webrecon report`` and the API;
* a live scan context (:func:`intel_from_ctx`) — ``webrecon scan --json/--html/--pdf``,
  which also works with ``--no-db``.

Both feed the same row shapes the API returns, so HTML, JSON and PDF reports show
the same sections as the dashboard. Parameter *values* are never included — only
names, inferred classes and where they were seen.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

from ..core.enums import ModuleStatus
from ..core.logging import get_logger
from ..intel.asset_graph import assemble_asset_graph
from ..intel.attack_surface import build_attack_surface
from ..intel.auth_flow import auth_flow_from_rows
from ..modules.api.params import INTERESTING_PARAMS

if TYPE_CHECKING:
    from ..core.context import ScanContext
    from ..storage.database import Database

#: Sort order for endpoint observation (most certain first).
OBSERVATION_RANK = {"observed": 0, "referenced": 1, "potential": 2}


def _endpoint_row(e: dict) -> dict[str, Any]:
    meta = e.get("meta") or {}
    params = meta.get("params") or []
    return {
        "url": e.get("url") or "",
        "method": e.get("method"),
        "kind": e.get("kind") or "rest",
        "observation": e.get("observation") or "potential",
        "discovery_status": meta.get("discovery_status") or "",
        "sources": meta.get("sources") or [s for s in (e.get("source") or "").split(",") if s],
        "params": [p.get("name") for p in params if p.get("name")],
        "sensitive_params": sorted({p.get("classification") for p in params}
                                   & INTERESTING_PARAMS),
    }


def aggregate_parameters(endpoints: list[dict]) -> list[dict[str, Any]]:
    """Merge per-endpoint parameter intel into one row per (name, class)."""
    merged: dict[tuple[str, str], dict[str, Any]] = {}
    for e in endpoints:
        for p in (e.get("meta") or {}).get("params") or []:
            name = p.get("name")
            if not name:
                continue
            cls = p.get("classification") or "unknown"
            row = merged.setdefault((name, cls), {
                "name": name, "classification": cls, "confidence": 0.0,
                "locations": set(), "endpoints": [],
                "sensitive": cls in INTERESTING_PARAMS,
            })
            row["confidence"] = max(row["confidence"], float(p.get("confidence") or 0))
            if p.get("source"):
                row["locations"].add(p["source"])
            if e.get("url") and e["url"] not in row["endpoints"]:
                row["endpoints"].append(e["url"])
    out = []
    for row in merged.values():
        out.append({**row, "locations": sorted(row["locations"]),
                    "endpoint_count": len(row["endpoints"]), "endpoints": row["endpoints"][:5],
                    "confidence": round(row["confidence"], 2)})
    out.sort(key=lambda r: (not r["sensitive"], -r["endpoint_count"], r["name"]))
    return out


def build_intel_sections(
    *,
    endpoints: list[dict],
    forms: list[dict],
    cookie_names: list[str],
    graph: dict[str, Any] | None,
) -> dict[str, Any]:
    """Pure: the four report sections plus a small summary."""
    rows = sorted((_endpoint_row(e) for e in endpoints),
                  key=lambda r: (OBSERVATION_RANK.get(r["observation"], 3), r["url"]))
    params = aggregate_parameters(endpoints)
    flow = auth_flow_from_rows(endpoints, forms, cookie_names).to_dict()
    tree = build_attack_surface(graph) if graph and graph.get("nodes") else None
    return {
        "summary": {
            "endpoints": len(rows),
            "observed": sum(r["observation"] == "observed" for r in rows),
            "static_only": sum(r["discovery_status"] == "STATIC_ONLY" for r in rows),
            "parameters": len(params),
            "sensitive_parameters": sum(p["sensitive"] for p in params),
            "auth_kind": flow.get("kind"),
            "attack_surface_findings": tree["finding_count"] if tree else 0,
        },
        "attack_surface": tree,
        "endpoints": rows,
        "parameters": params,
        "auth_flow": flow,
    }


def intel_from_rows(
    overview: dict[str, Any] | None,
    *,
    findings: list[dict],
    endpoints: list[dict],
    pages: list[dict],
    assets: list[dict],
    forms: list[dict],
    dns: list[dict],
    has_certificate: bool,
    cookie_names: list[str],
) -> dict[str, Any]:
    """Pure: asset graph + the four sections from already-loaded rows."""
    graph = None
    if overview is not None:
        graph = assemble_asset_graph(
            overview, dns=dns, has_certificate=has_certificate, pages=pages, forms=forms,
            assets=assets, endpoints=endpoints, findings=findings).to_dict()
    return build_intel_sections(endpoints=endpoints, forms=forms,
                                cookie_names=cookie_names, graph=graph)


async def intel_from_db(
    db: Database,
    scan_id: str,
    *,
    overview: dict[str, Any] | None = None,
    findings: list[dict] | None = None,
    endpoints: list[dict] | None = None,
    pages: list[dict] | None = None,
    assets: list[dict] | None = None,
) -> dict[str, Any]:
    """Sections for a stored scan; pass rows the caller already loaded to avoid re-querying."""
    from ..api import queries

    return intel_from_rows(
        overview if overview is not None else await queries.get_overview(db, scan_id),
        findings=findings if findings is not None else await queries.get_findings(db, scan_id),
        endpoints=(endpoints if endpoints is not None
                   else await queries.get_endpoints(db, scan_id)),
        pages=pages if pages is not None else await queries.get_pages(db, scan_id),
        assets=assets if assets is not None else await queries.get_assets(db, scan_id),
        forms=await queries.get_forms(db, scan_id),
        dns=await queries.get_dns(db, scan_id),
        has_certificate=bool(await queries.get_certificates(db, scan_id)),
        cookie_names=await queries.get_cookie_names(db, scan_id),
    )


def _ctx_endpoints(ctx: ScanContext) -> list[dict]:
    rows = []
    for e in ctx.shared.get("api_endpoints") or []:
        rows.append({
            "url": e.url, "method": next(iter(sorted(e.methods)), None), "kind": e.kind,
            "observation": str(e.observation), "source": ",".join(sorted(e.sources)),
            "meta": {"in_scope": e.in_scope, "sources": sorted(e.sources),
                     "params": e.param_meta, "discovery_status": e.discovery_status},
        })
    return rows


def intel_from_ctx(ctx: ScanContext, ip_intel: dict | None = None) -> dict[str, Any]:
    """Same sections from a live scan context (no database needed)."""
    endpoints = _ctx_endpoints(ctx)
    inv = ctx.shared.get("inventory")
    forms = [f.model_dump(mode="json") for f in inv.forms] if inv else []
    pages = [{"url": p.url, "status_code": p.status_code} for p in inv.pages] if inv else []
    assets = ([{"url": a.url, "asset_type": str(a.asset_type)} for a in inv.assets]
              if inv else [])
    cookies = ctx.result_of("cookies")
    tech = ctx.result_of("technology")
    overview = None
    if ctx.target is not None:
        overview = {"target": {"hostname": ctx.target.hostname}, "ip_intel": ip_intel,
                    "technologies": (tech.data.get("technologies", []) if tech else [])}
    return intel_from_rows(
        overview,
        findings=[f.model_dump(mode="json") for f in ctx.all_findings()],
        endpoints=endpoints, pages=pages, assets=assets, forms=forms,
        dns=_ctx_dns_rows(ctx), has_certificate=_ctx_has_certificate(ctx),
        cookie_names=list((cookies.data or {}).get("names", [])) if cookies else [],
    )


def _ctx_dns_rows(ctx: ScanContext) -> list[dict]:
    """DNS records as the ``dns_records`` rows the stored-scan path uses."""
    dns = ctx.result_of("dns")
    if dns is None or ctx.target is None:
        return []
    records = (dns.data or {}).get("records") or {}
    return [{"name": ctx.target.hostname, "record_type": rtype, "value": value}
            for rtype, values in records.items() for value in values]


def _ctx_has_certificate(ctx: ScanContext) -> bool:
    """A certificate was actually parsed (skipped/failed TLS runs still set ``data``)."""
    tls = ctx.result_of("tls")
    return bool(tls and tls.status == ModuleStatus.SUCCESS
                and "skipped" not in (tls.data or {}) and tls.data.get("subject") is not None)


def safe_intel_from_ctx(ctx: ScanContext, ip_intel: dict | None = None) -> dict[str, Any] | None:
    """Like :func:`intel_from_ctx` but never raises — a scan's results must not be lost."""
    try:
        return intel_from_ctx(ctx, ip_intel)
    except Exception as exc:  # noqa: BLE001 - report sections are best-effort
        get_logger("report").warning("intel sections failed", error=f"{type(exc).__name__}: {exc}")
        return None
