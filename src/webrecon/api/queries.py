"""Read queries backing the dashboard API.

Return plain JSON-able dicts so the API layer stays thin. All reads go through
the SQLAlchemy ORM (bound parameters — threat T6).
"""

from __future__ import annotations

import re
from typing import Any

from sqlalchemy import func, select

from ..storage.database import Database
from ..storage.models import (
    Asset,
    Certificate,
    DnsRecord,
    Endpoint,
    EvidenceRecord,
    FindingRecord,
    Form,
    IpIntelRecord,
    ModuleRun,
    Page,
    Scan,
    ScanEventRecord,
    Target,
    Technology,
)

_SEVERITY_RANK = {
    "critical": 4, "high": 3, "medium": 2, "low": 1, "informational": 0,
}


def filter_report_min_severity(rep: dict[str, Any], min_severity: str) -> dict[str, Any]:
    """Return a copy of a report keeping only findings at/above ``min_severity``.

    Recomputes ``summary`` counts so the filtered report stays internally
    consistent (HTML/PDF render off the same dict). Unknown severities are
    treated as the floor (never dropped) so a bad value can't hide findings.
    """
    threshold = _SEVERITY_RANK.get(min_severity.lower())
    if threshold is None:
        return rep  # unrecognized floor → no filtering (fail-open, keep all)

    kept = [
        f for f in rep.get("findings", [])
        if _SEVERITY_RANK.get(str(f.get("severity", "")).lower(), 0) >= threshold
    ]
    by_severity = {k: 0 for k in _SEVERITY_RANK}
    for f in kept:
        sev = str(f.get("severity", "")).lower()
        if sev in by_severity:
            by_severity[sev] += 1

    out = dict(rep)
    out["findings"] = kept
    summary = dict(rep.get("summary", {}))
    summary["total_findings"] = len(kept)
    summary["by_severity"] = by_severity
    summary["min_severity"] = min_severity.lower()
    out["summary"] = summary
    return out


async def list_scans(db: Database) -> list[dict[str, Any]]:
    async with db.session() as s:
        rows = (
            await s.execute(select(Scan, Target).join(Target, Scan.target_id == Target.id))
        ).all()
        out = []
        for scan, target in sorted(rows, key=lambda r: r[0].created_at, reverse=True):
            fcount = await s.scalar(
                select(func.count()).select_from(FindingRecord).where(
                    FindingRecord.scan_id == scan.id
                )
            )
            out.append(
                {
                    "id": scan.id,
                    "target": target.base_url,
                    "status": scan.status,
                    "created_at": scan.created_at.isoformat(),
                    "finished_at": scan.finished_at.isoformat() if scan.finished_at else None,
                    "findings": fcount or 0,
                }
            )
        return out


async def get_overview(db: Database, scan_id: str) -> dict[str, Any] | None:
    async with db.session() as s:
        scan = await s.get(Scan, scan_id)
        if scan is None:
            return None
        target = await s.get(Target, scan.target_id)
        runs = (
            await s.execute(select(ModuleRun).where(ModuleRun.scan_id == scan_id))
        ).scalars().all()
        findings = (
            await s.execute(select(FindingRecord).where(FindingRecord.scan_id == scan_id))
        ).scalars().all()
        by_sev: dict[str, int] = {}
        for f in findings:
            by_sev[f.severity] = by_sev.get(f.severity, 0) + 1
        security_run = next((r for r in runs if r.module == "security"), None)
        risk_level = (security_run.stats or {}).get("risk_level") if security_run else None
        techs = (
            await s.execute(select(Technology).where(Technology.scan_id == scan_id))
        ).scalars().all()
        ip_row = (
            await s.execute(select(IpIntelRecord).where(IpIntelRecord.scan_id == scan_id))
        ).scalars().first()
        ip_intel = (
            {"edge_cdn": ip_row.edge_cdn, "origin_exposed": ip_row.origin_exposed,
             "ips": ip_row.ips}
            if ip_row is not None else None
        )
        return {
            "id": scan.id,
            "status": scan.status,
            "target": {
                "base_url": target.base_url if target else None,
                "hostname": target.hostname if target else None,
                "scheme": target.scheme if target else None,
            },
            "created_at": scan.created_at.isoformat(),
            "finished_at": scan.finished_at.isoformat() if scan.finished_at else None,
            "risk_level": risk_level,
            "findings_by_severity": by_sev,
            "total_findings": len(findings),
            "modules": [
                {
                    "module": r.module,
                    "status": r.status,
                    "duration_ms": r.duration_ms,
                    "error": r.error,
                }
                for r in sorted(runs, key=lambda r: r.created_at)
            ],
            "technologies": [
                {"name": t.name, "category": t.category, "version": t.version,
                 "confidence": t.confidence}
                for t in techs
            ],
            "ip_intel": ip_intel,
        }


async def get_findings(db: Database, scan_id: str) -> list[dict[str, Any]]:
    async with db.session() as s:
        rows = (
            await s.execute(select(FindingRecord).where(FindingRecord.scan_id == scan_id))
        ).scalars().all()
        out = []
        for f in sorted(rows, key=lambda f: _SEVERITY_RANK.get(f.severity, 0), reverse=True):
            evidence = (
                await s.execute(select(EvidenceRecord).where(EvidenceRecord.finding_id == f.id))
            ).scalars().all()
            out.append(
                {
                    "id": f.id,
                    "check_id": f.check_id,
                    "name": f.name,
                    "category": f.category,
                    "severity": f.severity,
                    "confidence": f.confidence,
                    "observation": f.observation,
                    "description": f.description,
                    "impact": f.impact,
                    "recommendation": f.recommendation,
                    "module": f.module,
                    "references": f.references,
                    "evidence": [
                        {"source": e.source, "url": e.url, "description": e.description,
                         "data": e.data}
                        for e in evidence
                    ],
                }
            )
        return out


async def _simple_list(db: Database, model, scan_id: str, fields: list[str]) -> list[dict]:
    async with db.session() as s:
        rows = (
            await s.execute(select(model).where(model.scan_id == scan_id))
        ).scalars().all()
        return [{f: getattr(r, f) for f in fields} for r in rows]


async def get_assets(db: Database, scan_id: str) -> list[dict]:
    return await _simple_list(
        db, Asset, scan_id,
        ["asset_type", "url", "observation", "content_hash", "size_bytes", "meta"],
    )


async def get_endpoints(db: Database, scan_id: str) -> list[dict]:
    return await _simple_list(
        db, Endpoint, scan_id, ["url", "method", "kind", "observation", "source", "meta"]
    )


async def get_pages(db: Database, scan_id: str) -> list[dict]:
    return await _simple_list(
        db, Page, scan_id,
        ["url", "title", "status_code", "depth", "content_hash", "discovered_from"],
    )


async def get_technologies(db: Database, scan_id: str) -> list[dict]:
    return await _simple_list(
        db, Technology, scan_id, ["name", "category", "version", "confidence", "evidence"]
    )


async def get_dns(db: Database, scan_id: str) -> list[dict]:
    return await _simple_list(db, DnsRecord, scan_id, ["name", "record_type", "value"])


async def get_certificates(db: Database, scan_id: str) -> list[dict]:
    return await _simple_list(
        db, Certificate, scan_id, ["subject", "issuer", "san", "not_before", "not_after", "details"]
    )


async def get_forms(db: Database, scan_id: str) -> list[dict]:
    return await _simple_list(
        db, Form, scan_id, ["page_url", "action", "method", "enctype", "inputs"]
    )


async def diff_scans(db: Database, scan_id: str, against_id: str) -> dict[str, Any]:
    """Compare two scans (§26 timeline): what changed between `against` → `scan`."""

    async def _sets(sid: str):
        eps = {e["url"] for e in await get_endpoints(db, sid)}
        techs = {
            f"{t['name']} {t['version'] or ''}".strip()
            for t in await get_technologies(db, sid)
        }
        finds = {f["check_id"] for f in await get_findings(db, sid)}
        return eps, techs, finds

    new_eps, new_techs, new_finds = await _sets(scan_id)
    old_eps, old_techs, old_finds = await _sets(against_id)

    def _delta(new: set, old: set) -> dict:
        return {"added": sorted(new - old), "removed": sorted(old - new)}

    return {
        "from": against_id,
        "to": scan_id,
        "endpoints": _delta(new_eps, old_eps),
        "technologies": _delta(new_techs, old_techs),
        "findings": _delta(new_finds, old_finds),
    }


_SESSION_COOKIE = re.compile(
    r"session|sess|sid|auth|token|jsessionid|phpsessid|connect\.sid|csrftoken", re.I)


async def get_auth_flow(db: Database, scan_id: str) -> dict[str, Any]:
    """Build the detection-only authentication-flow model for a scan."""
    from ..intel.auth_flow import build_auth_flow
    from ..storage.models import Cookie

    endpoints = await get_endpoints(db, scan_id)
    forms = await get_forms(db, scan_id)
    has_login_form = any(
        str(i.get("type") or "").lower() == "password"
        for fm in forms for i in (fm.get("inputs") or [])
    )
    async with db.session() as s:
        cookies = (
            await s.execute(select(Cookie).where(Cookie.scan_id == scan_id))
        ).scalars().all()
    has_session_cookie = any(_SESSION_COOKIE.search(c.name or "") for c in cookies)
    flow = build_auth_flow(
        endpoints, has_login_form=has_login_form, has_session_cookie=has_session_cookie)
    return flow.to_dict()


async def get_graph(db: Database, scan_id: str) -> dict[str, Any]:
    """Unified asset graph from persisted entities (§25).

    Backed by the typed asset-graph builder; the returned shape keeps the
    ``{nodes:[{id,label,type,...}], edges:[{source,target,relation,...}]}``
    contract the dashboard renders, now enriched with provenance/confidence.
    """
    from ..intel.asset_graph import build_asset_graph

    graph = await build_asset_graph(db, scan_id)
    return graph.to_dict()


async def get_events(db: Database, scan_id: str, kind: str | None = None) -> list[dict[str, Any]]:
    """Scan timeline (G6) in emission order, optionally filtered to one ``kind``."""
    async with db.session() as s:
        stmt = select(ScanEventRecord).where(ScanEventRecord.scan_id == scan_id)
        if kind:
            stmt = stmt.where(ScanEventRecord.kind == kind)
        rows = (await s.execute(stmt.order_by(ScanEventRecord.seq))).scalars().all()
        return [
            {"seq": r.seq, "ts": r.ts.isoformat() if r.ts else None, "kind": r.kind,
             "module": r.module, "label": r.label, "data": r.data or {}}
            for r in rows
        ]


async def get_js_files(db: Database, scan_id: str) -> list[dict[str, Any]]:
    """JS Explorer rows: every script asset, flattened with its analysis (if fetched)."""
    from urllib.parse import urlsplit

    out: list[dict[str, Any]] = []
    for a in await get_assets(db, scan_id):
        if a["asset_type"] != "script":
            continue
        js = (a.get("meta") or {}).get("js") or {}
        try:
            host = urlsplit(a["url"]).hostname or ""
        except ValueError:
            host = ""
        out.append({
            "url": a["url"], "host": host, "observation": a["observation"],
            "sha256": a.get("content_hash"), "size": a.get("size_bytes"),
            "analyzed": bool(js.get("analyzed")),
            "frameworks": js.get("frameworks", []),
            "endpoints": js.get("endpoints", []),
            "ast_calls": js.get("ast_calls", []),
            "websockets": js.get("websockets", []),
            "graphql": bool(js.get("graphql")),
            "secrets": js.get("secrets", 0),
            "sourcemap": js.get("sourcemap"),
            "sourcemap_exposed": bool(js.get("sourcemap_exposed")),
            "reconstructed_files": js.get("reconstructed_files", 0),
            "truncated": bool(js.get("truncated")),
        })
    # Analyzed files first, then the largest — the most interesting rows on top.
    out.sort(key=lambda r: (not r["analyzed"], -(r["size"] or 0), r["url"]))
    return out


async def get_attack_surface(db: Database, scan_id: str) -> dict[str, Any]:
    """Hierarchical attack-surface tree derived from the unified asset graph."""
    from ..intel.attack_surface import build_attack_surface

    return build_attack_surface(await get_graph(db, scan_id))
