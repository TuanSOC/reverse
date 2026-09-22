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
    DnsRecord,
    EvidenceRecord,
    FindingRecord,
    Form,
    ModuleRun,
    Page,
    Scan,
    Target,
)

if TYPE_CHECKING:
    from ..modules.crawler.models import CrawlInventory
    from ..modules.tls.analysis import CertInfo


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

    async def finalize_scan(self, scan_id: str, status: str) -> None:
        from sqlalchemy import update

        from .models import _utcnow

        async with self.db.session() as s:
            await s.execute(
                update(Scan)
                .where(Scan.id == scan_id)
                .values(status=status, finished_at=_utcnow())
            )
