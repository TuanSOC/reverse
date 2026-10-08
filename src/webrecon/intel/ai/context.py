"""Normalized, citation-ready evidence for the AI layer (G8).

The model never sees the raw target. It sees an :class:`AnalysisContext`: a
bounded list of evidence items distilled from the stored scan, each with a
stable ID (``F1`` finding, ``E1`` endpoint, ``T1`` technology, ``J1`` script,
``M1`` form, ``A1`` auth flow, ``S1`` scan coverage, ``X1`` target). IDs are
deterministic for a given scan, so a claim's citations can always be resolved
back to stored data.

Hygiene: query-string *values* are masked in every URL, form inputs carry only
name/type, and finding evidence payloads are not forwarded — only the finding's
identity, rating and location.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

from ...api import queries
from ...storage.database import Database

# Caps keep the prompt within a free-tier token budget on large sites.
MAX_ENDPOINTS = 50
MAX_FINDINGS = 40
MAX_TECH = 25
MAX_JS = 10
MAX_FORMS = 10

_SEV_RANK = {"critical": 4, "high": 3, "medium": 2, "low": 1, "informational": 0}
_OBS_RANK = {"observed": 0, "referenced": 1, "potential": 2}
# Parameter classes that make an endpoint security-relevant (re-exported).
from ...modules.api.params import INTERESTING_PARAMS  # noqa: E402,F401


@dataclass
class EvidenceItem:
    id: str
    kind: str        # target|stats|technology|endpoint|finding|script|form|auth
    summary: str     # one line the model reads
    data: dict[str, Any] = field(default_factory=dict)  # structured facts for the UI

    def to_dict(self) -> dict[str, Any]:
        return {"id": self.id, "kind": self.kind, "summary": self.summary, "data": self.data}


@dataclass
class AnalysisContext:
    scan_id: str
    target: str
    items: list[EvidenceItem] = field(default_factory=list)

    @property
    def ids(self) -> set[str]:
        return {i.id for i in self.items}

    def get(self, item_id: str) -> EvidenceItem | None:
        return next((i for i in self.items if i.id == item_id), None)

    def of_kind(self, kind: str) -> list[EvidenceItem]:
        return [i for i in self.items if i.kind == kind]

    def to_prompt_payload(self) -> dict[str, Any]:
        """Compact form sent to the model: id + kind + one-line summary only."""
        return {"target": self.target,
                "evidence": [{"id": i.id, "kind": i.kind, "s": i.summary} for i in self.items]}


def mask_query(url: str) -> str:
    """Keep parameter names, replace values with ``*`` (tokens can live in queries)."""
    try:
        p = urlsplit(url)
    except ValueError:
        return url
    if not p.query:
        return url
    masked = urlencode([(k, "*") for k, _ in parse_qsl(p.query, keep_blank_values=True)],
                       safe="*")
    return urlunsplit((p.scheme, p.netloc, p.path, masked, p.fragment))


def assemble_context(
    scan_id: str,
    *,
    overview: dict[str, Any],
    findings: list[dict],
    endpoints: list[dict],
    js_files: list[dict],
    forms: list[dict],
    auth_flow: dict[str, Any],
    page_count: int,
) -> AnalysisContext:
    """Pure: build the context from already-queried rows (unit-testable)."""
    target = (overview.get("target") or {}).get("base_url") or ""
    ctx = AnalysisContext(scan_id=scan_id, target=target)
    add = ctx.items.append

    ip = overview.get("ip_intel") or {}
    first_ip = (ip.get("ips") or [{}])[0]
    add(EvidenceItem("X1", "target",
                     f"target {target}; risk level {overview.get('risk_level') or 'unknown'}"
                     + (f"; edge CDN {ip['edge_cdn']}" if ip.get("edge_cdn") else "")
                     + (f"; hosted by {first_ip['provider']}" if first_ip.get("provider") else ""),
                     {"base_url": target,
                      "hostname": (overview.get("target") or {}).get("hostname"),
                      "risk_level": overview.get("risk_level"), "edge_cdn": ip.get("edge_cdn")}))

    by_obs: dict[str, int] = {}
    for e in endpoints:
        by_obs[e.get("observation") or "?"] = by_obs.get(e.get("observation") or "?", 0) + 1
    modules = overview.get("modules") or []
    not_ok = sorted(f"{m['module']}={m['status']}" for m in modules
                    if m.get("status") not in ("success",))
    analyzed_js = [j for j in js_files if j.get("analyzed")]
    stats = {
        "pages": page_count, "endpoints": len(endpoints), "endpoints_by_observation": by_obs,
        "scripts": len(js_files), "scripts_analyzed": len(analyzed_js),
        "findings": len(findings), "modules_not_successful": not_ok,
        "truncated": {"endpoints": len(endpoints) > MAX_ENDPOINTS,
                      "findings": len(findings) > MAX_FINDINGS},
    }
    add(EvidenceItem(
        "S1", "stats",
        f"coverage: {page_count} pages crawled, {len(endpoints)} endpoints "
        f"({', '.join(f'{k} {v}' for k, v in sorted(by_obs.items())) or 'none'}), "
        f"{len(analyzed_js)}/{len(js_files)} scripts analyzed, {len(findings)} findings; "
        f"modules not fully successful: {', '.join(not_ok) or 'none'}",
        stats))

    for n, t in enumerate((overview.get("technologies") or [])[:MAX_TECH], 1):
        name = f"{t['name']} {t.get('version') or ''}".strip()
        add(EvidenceItem(f"T{n}", "technology",
                         f"{name} ({t.get('category') or 'uncategorized'}, "
                         f"{t.get('confidence')} confidence)", dict(t)))

    eps = sorted(endpoints, key=lambda e: (_OBS_RANK.get(e.get("observation") or "", 3),
                                           e.get("url") or ""))
    for n, e in enumerate(eps[:MAX_ENDPOINTS], 1):
        meta = e.get("meta") or {}
        classes = sorted({p.get("classification") for p in meta.get("params") or []
                          if p.get("classification")} - {"unknown"})
        url = mask_query(e.get("url") or "")
        status = meta.get("discovery_status") or ""
        add(EvidenceItem(
            f"E{n}", "endpoint",
            f"{e.get('method') or e.get('kind', 'rest').upper()} {url} [{e.get('observation')}"
            + (f", {status.lower()}" if status else "") + "]"
            + (f" params: {', '.join(classes)}" if classes else ""),
            {"url": url, "method": e.get("method"), "kind": e.get("kind"),
             "observation": e.get("observation"), "discovery_status": status,
             "param_classes": classes}))

    fs = sorted(findings, key=lambda f: (-_SEV_RANK.get(f.get("severity") or "", 0),
                                        f.get("check_id") or "", f.get("id") or ""))
    for n, f in enumerate(fs[:MAX_FINDINGS], 1):
        loc = next((ev.get("url") for ev in f.get("evidence") or [] if ev.get("url")), None)
        loc = mask_query(loc) if loc else None
        add(EvidenceItem(
            f"F{n}", "finding",
            f"{f.get('severity')}/{f.get('confidence')} {f.get('observation')}: "
            f"{f.get('name')} ({f.get('check_id')})" + (f" at {loc}" if loc else ""),
            {"finding_id": f.get("id"), "check_id": f.get("check_id"), "name": f.get("name"),
             "severity": f.get("severity"), "confidence": f.get("confidence"),
             "observation": f.get("observation"), "category": f.get("category"),
             "module": f.get("module"), "location": loc}))

    for n, j in enumerate(analyzed_js[:MAX_JS], 1):
        bits = [f"{len(j.get('endpoints') or [])} regex endpoints",
                f"{len(j.get('ast_calls') or [])} AST calls"]
        if j.get("frameworks"):
            bits.append("frameworks " + ", ".join(j["frameworks"][:4]))
        if j.get("sourcemap_exposed"):
            bits.append(f"source map exposed ({j.get('reconstructed_files', 0)} sources rebuilt)")
        if j.get("secrets"):
            bits.append(f"{j['secrets']} secret-like strings (masked)")
        url = mask_query(j.get("url") or "")
        add(EvidenceItem(f"J{n}", "script", f"script {url}: " + "; ".join(bits),
                         {"url": url, "size": j.get("size"), "frameworks": j.get("frameworks"),
                          "sourcemap_exposed": j.get("sourcemap_exposed"),
                          "reconstructed_files": j.get("reconstructed_files"),
                          "secrets": j.get("secrets")}))

    for n, fm in enumerate(forms[:MAX_FORMS], 1):
        inputs = [{"name": i.get("name"), "type": i.get("type")} for i in fm.get("inputs") or []]
        names = ", ".join(f"{i['name']}:{i['type']}" for i in inputs if i.get("name"))
        add(EvidenceItem(
            f"M{n}", "form",
            f"form {(fm.get('method') or 'get').upper()} -> {mask_query(fm.get('action') or '')} "
            f"on {mask_query(fm.get('page_url') or '')}" + (f" inputs: {names}" if names else ""),
            {"page_url": mask_query(fm.get("page_url") or ""),
             "action": mask_query(fm.get("action") or ""), "method": fm.get("method"),
             "inputs": inputs}))

    auth_eps = auth_flow.get("endpoints") or []
    add(EvidenceItem(
        "A1", "auth",
        f"auth flow model: {auth_flow.get('kind', 'unknown')} "
        f"(confidence {auth_flow.get('confidence', 0)}); login form "
        f"{'present' if auth_flow.get('has_login_form') else 'absent'}; session cookie "
        f"{'present' if auth_flow.get('has_session_cookie') else 'absent'}; auth endpoints: "
        + (", ".join(f"{e.get('role')} {mask_query(e.get('url') or '')}" for e in auth_eps)
           or "none"),
        {"kind": auth_flow.get("kind"), "confidence": auth_flow.get("confidence"),
         "steps": auth_flow.get("steps"), "has_login_form": auth_flow.get("has_login_form"),
         "has_session_cookie": auth_flow.get("has_session_cookie"),
         "endpoints": [{**e, "url": mask_query(e.get("url") or "")} for e in auth_eps]}))
    return ctx


async def build_analysis_context(db: Database, scan_id: str) -> AnalysisContext | None:
    """Query the stored scan and assemble its context; ``None`` if the scan is unknown."""
    overview = await queries.get_overview(db, scan_id)
    if overview is None:
        return None
    return assemble_context(
        scan_id,
        overview=overview,
        findings=await queries.get_findings(db, scan_id),
        endpoints=await queries.get_endpoints(db, scan_id),
        js_files=await queries.get_js_files(db, scan_id),
        forms=await queries.get_forms(db, scan_id),
        auth_flow=await queries.get_auth_flow(db, scan_id),
        page_count=len(await queries.get_pages(db, scan_id)),
    )
