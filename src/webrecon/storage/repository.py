"""Persistence helpers mapping runtime models to ORM rows.

Keeps SQL out of the pipeline: the orchestrator hands finished results here and
the repository writes targets, scans, module runs, findings, and evidence in one
place. All writes go through the SQLAlchemy ORM (bound parameters — no string
SQL), addressing threat T6.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from ..core.models import ModuleResult, TargetInfo
from .database import Database
from .models import (
    Asset,
    Certificate,
    Cookie,
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

if TYPE_CHECKING:
    from ..core.context import ScanEvent
    from ..modules.api.classify import Endpoint as EndpointDTO
    from ..modules.crawler.models import CrawlInventory
    from ..modules.javascript.analysis import JsAnalysis
    from ..modules.technology.fingerprint import TechDetection
    from ..modules.tls.analysis import CertInfo


#: Per-file cap on list fields copied into ``assets.meta["js"]``.
_JS_LIST_CAP = 200


class ScanRepository:
    """Writes scan artifacts to the database."""

    def __init__(self, db: Database) -> None:
        self.db = db

    async def create_target_and_scan(
        self, target: TargetInfo, scan_id: str, config: dict
    ) -> tuple[str, str]:
        """Persist the target + a new scan row; return (target_id, scan_id)."""
        async with self.db.session() as s:
            row = Target(
                input_url=target.input_url,
                scheme=target.scheme,
                hostname=target.hostname,
                port=target.port,
                base_url=target.base_url,
                canonical_url=target.canonical_url,
            )
            s.add(row)
            await s.flush()
            scan = Scan(id=scan_id, target_id=row.id, status="running", config=config)
            s.add(scan)
            await s.flush()
            return row.id, scan.id

    async def save_module_result(self, scan_id: str, result: ModuleResult) -> None:
        """Persist a module run plus its findings and evidence."""
        async with self.db.session() as s:
            s.add(
                ModuleRun(
                    scan_id=scan_id,
                    module=result.module,
                    version=result.version,
                    status=str(result.status),
                    started_at=result.started_at,
                    finished_at=result.finished_at,
                    duration_ms=result.duration_ms,
                    error=result.error,
                    stats=result.stats,
                )
            )
            for f in result.findings:
                finding = FindingRecord(
                    id=f.id,  # same id as the live report / timeline
                    scan_id=scan_id,
                    check_id=f.check_id,
                    name=f.name,
                    category=str(f.category),
                    severity=str(f.severity),
                    confidence=str(f.confidence),
                    observation=str(f.observation),
                    description=f.description,
                    impact=f.impact,
                    recommendation=f.recommendation,
                    module=f.module,
                    references=list(f.references),
                )
                s.add(finding)
                await s.flush()
                for ev in f.evidence:
                    s.add(
                        EvidenceRecord(
                            id=ev.id,
                            scan_id=scan_id,
                            finding_id=finding.id,
                            source=ev.source,
                            url=ev.url,
                            description=ev.description,
                            data=ev.data,
                        )
                    )
            # Module-level evidence not attached to a finding.
            for ev in result.evidence:
                s.add(
                    EvidenceRecord(
                        scan_id=scan_id,
                        finding_id=None,
                        source=ev.source,
                        url=ev.url,
                        description=ev.description,
                        data=ev.data,
                    )
                )

    async def save_crawl(self, scan_id: str, inv: CrawlInventory) -> None:
        """Persist crawled pages, discovered assets, and forms."""
        async with self.db.session() as s:
            for p in inv.pages:
                s.add(
                    Page(
                        scan_id=scan_id,
                        url=p.url,
                        title=p.title,
                        status_code=p.status_code,
                        depth=p.depth,
                        content_hash=p.content_hash,
                        discovered_from=p.discovered_from,
                    )
                )
            for a in inv.assets:
                s.add(
                    Asset(
                        scan_id=scan_id,
                        asset_type=str(a.asset_type),
                        url=a.url,
                        observation=str(a.observation),
                        meta=a.attrs,
                    )
                )
            for f in inv.forms:
                s.add(
                    Form(
                        scan_id=scan_id,
                        page_url=f.page_url,
                        action=f.action,
                        method=f.method,
                        enctype=f.enctype,
                        inputs=f.inputs,
                    )
                )

    async def save_dns_records(
        self, scan_id: str, host: str, records: dict[str, list[str]]
    ) -> None:
        async with self.db.session() as s:
            for rtype, values in records.items():
                for value in values:
                    s.add(
                        DnsRecord(scan_id=scan_id, name=host, record_type=rtype, value=value)
                    )

    async def save_ip_intel(
        self, scan_id: str, *, edge_cdn: str | None, origin_exposed: bool, ips: list[dict]
    ) -> None:
        async with self.db.session() as s:
            s.add(
                IpIntelRecord(
                    scan_id=scan_id, edge_cdn=edge_cdn,
                    origin_exposed=origin_exposed, ips=ips,
                )
            )

    async def save_certificate(self, scan_id: str, info: CertInfo) -> None:
        async with self.db.session() as s:
            s.add(
                Certificate(
                    scan_id=scan_id,
                    subject=info.subject,
                    issuer=info.issuer,
                    san=info.san,
                    not_before=info.not_before,
                    not_after=info.not_after,
                    details={"self_signed": info.self_signed, "serial": info.serial},
                )
            )

    async def save_technologies(self, scan_id: str, detections: list[TechDetection]) -> None:
        async with self.db.session() as s:
            for d in detections:
                s.add(
                    Technology(
                        scan_id=scan_id,
                        name=d.name,
                        category=d.category,
                        version=d.version,
                        confidence=str(d.confidence),
                        evidence=[
                            {"source": e.source, "detail": e.detail, "version": e.version}
                            for e in d.evidence
                        ],
                    )
                )

    async def save_endpoints(self, scan_id: str, endpoints: list[EndpointDTO]) -> None:
        async with self.db.session() as s:
            for e in endpoints:
                s.add(
                    Endpoint(
                        scan_id=scan_id,
                        url=e.url,
                        method=next(iter(sorted(e.methods)), None),
                        kind=e.kind,
                        observation=str(e.observation),
                        source=",".join(sorted(e.sources)),
                        meta={"in_scope": e.in_scope, "sources": sorted(e.sources),
                              "params": e.param_meta, "discovery_status": e.discovery_status},
                    )
                )

    async def save_js_analyses(self, scan_id: str, analyses: list[JsAnalysis]) -> None:
        """Attach JS analysis to the crawler's script asset rows (JS Explorer).

        Enriches the existing ``assets`` rows in place (hash/size columns plus a
        ``meta["js"]`` block) instead of adding a table; a script fetched but not
        recorded by the crawler gets a fresh row. Secret values are never stored —
        only the count of masked hits.
        """
        from sqlalchemy import select

        async with self.db.session() as s:
            rows = (
                await s.execute(
                    select(Asset).where(Asset.scan_id == scan_id, Asset.asset_type == "script")
                )
            ).scalars().all()
            by_url = {r.url: r for r in rows}
            for a in analyses:
                js = {
                    "analyzed": True,
                    "frameworks": list(a.framework_clues),
                    "endpoints": list(a.endpoints)[:_JS_LIST_CAP],
                    "ast_calls": list(a.ast_calls)[:_JS_LIST_CAP],
                    "websockets": list(a.websockets)[:_JS_LIST_CAP],
                    "graphql": a.graphql,
                    "secrets": len(a.secrets),
                    "sourcemap": a.sourcemap_url,
                    "sourcemap_exposed": a.sourcemap_exposed,
                    "reconstructed_files": a.reconstructed_files,
                    "truncated": a.truncated,
                }
                row = by_url.get(a.url)
                if row is None:
                    row = Asset(scan_id=scan_id, asset_type="script", url=a.url, meta={})
                    s.add(row)
                    by_url[a.url] = row
                row.observation = "observed"  # fetched + parsed, not just referenced
                row.content_hash = a.sha256
                row.size_bytes = a.size
                # Reassign (not mutate) so the JSON column change is tracked.
                row.meta = {**(row.meta or {}), "js": js}

    async def save_cookies(self, scan_id: str, cookies: list) -> None:
        """Persist cookie names + flags from Set-Cookie (values are never stored)."""
        async with self.db.session() as s:
            for c in cookies:
                s.add(Cookie(scan_id=scan_id, name=c.name, domain=c.domain, path=c.path,
                             secure=c.secure, http_only=c.http_only, same_site=c.same_site))

    async def save_events(self, scan_id: str, events: list[ScanEvent]) -> None:
        """Append timeline events (the pipeline flushes them incrementally)."""
        if not events:
            return
        async with self.db.session() as s:
            for ev in events:
                s.add(
                    ScanEventRecord(
                        scan_id=scan_id, seq=ev.seq, ts=ev.ts, kind=ev.kind,
                        module=ev.module, label=ev.label, data=ev.data,
                    )
                )

    async def finalize_scan(self, scan_id: str, status: str) -> None:
        from sqlalchemy import update

        from .models import _utcnow

        async with self.db.session() as s:
            await s.execute(
                update(Scan)
                .where(Scan.id == scan_id)
                .values(status=status, finished_at=_utcnow())
            )

    async def delete_scan(self, scan_id: str) -> bool:
        """Delete a scan and every row it owns; drop an orphaned target too.

        Returns ``False`` if the scan did not exist. Children are removed before
        parents so the delete holds regardless of FK-enforcement settings.
        """
        from sqlalchemy import delete, func, select

        from .models import (
            AiAnalysisRecord,
            Certificate,
            Cookie,
            DnsRecord,
            EvidenceRecord,
            IpIntelRecord,
            RequestRecord,
            ResponseRecord,
            ScanEventRecord,
        )

        # child-first order (evidence→findings, responses→requests, then the rest)
        scoped = [
            EvidenceRecord, FindingRecord, ResponseRecord, RequestRecord, ModuleRun,
            Page, Asset, Technology, DnsRecord, IpIntelRecord, Certificate, Endpoint,
            Form, Cookie, ScanEventRecord, AiAnalysisRecord,
        ]
        async with self.db.session() as s:
            scan = await s.get(Scan, scan_id)
            if scan is None:
                return False
            target_id = scan.target_id
            for model in scoped:
                await s.execute(delete(model).where(model.scan_id == scan_id))  # type: ignore[attr-defined]
            await s.execute(delete(Scan).where(Scan.id == scan_id))
            # Remove the target if no other scan references it.
            remaining = await s.scalar(
                select(func.count()).select_from(Scan).where(Scan.target_id == target_id))
            if not remaining:
                await s.execute(delete(Target).where(Target.id == target_id))
        _delete_screenshot(scan_id)
        return True


def _delete_screenshot(scan_id: str) -> None:
    """Best-effort removal of a scan's screenshot file."""
    from pathlib import Path

    with __import__("contextlib").suppress(OSError):
        p = Path("scans/screenshots") / f"{scan_id}.png"
        if p.exists():
            p.unlink()
