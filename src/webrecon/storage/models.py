"""SQLAlchemy 2.0 ORM models — the local scan database (§27).

Every record has a UUID primary key, a ``created_at`` timestamp, and (except
the roots) a ``scan_id`` foreign key, so results are always attributable to a
scan and comparable across scans (§26 timeline). Flexible per-record payloads
live in JSON columns to keep the schema stable as modules evolve.
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime

from sqlalchemy import JSON, DateTime, Float, ForeignKey, Integer, String, Text
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, relationship


def _uuid() -> str:
    return str(uuid.uuid4())


def _utcnow() -> datetime:
    return datetime.now(UTC)


class Base(DeclarativeBase):
    pass


class IdMixin:
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_uuid)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_utcnow)


class ScanScopedMixin(IdMixin):
    @classmethod
    def _scan_fk(cls) -> Mapped[str]:  # pragma: no cover - helper only
        return mapped_column(String(36), ForeignKey("scans.id"), index=True)


class Target(IdMixin, Base):
    __tablename__ = "targets"

    input_url: Mapped[str] = mapped_column(Text)
    scheme: Mapped[str] = mapped_column(String(16))
    hostname: Mapped[str] = mapped_column(String(255), index=True)
    port: Mapped[int] = mapped_column(Integer)
    base_url: Mapped[str] = mapped_column(Text)
    canonical_url: Mapped[str | None] = mapped_column(Text, nullable=True)

    scans: Mapped[list[Scan]] = relationship(back_populates="target")


class Scan(IdMixin, Base):
    __tablename__ = "scans"

    target_id: Mapped[str] = mapped_column(String(36), ForeignKey("targets.id"), index=True)
    status: Mapped[str] = mapped_column(String(16), default="pending")
    started_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    finished_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    config: Mapped[dict] = mapped_column(JSON, default=dict)

    target: Mapped[Target] = relationship(back_populates="scans")
    module_runs: Mapped[list[ModuleRun]] = relationship(
        back_populates="scan", cascade="all, delete-orphan"
    )
    findings: Mapped[list[FindingRecord]] = relationship(
        back_populates="scan", cascade="all, delete-orphan"
    )


class ModuleRun(IdMixin, Base):
    __tablename__ = "module_runs"

    scan_id: Mapped[str] = mapped_column(String(36), ForeignKey("scans.id"), index=True)
    module: Mapped[str] = mapped_column(String(64), index=True)
    version: Mapped[str] = mapped_column(String(32), default="0.0.0")
    status: Mapped[str] = mapped_column(String(16), default="pending")
    started_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    finished_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    duration_ms: Mapped[float | None] = mapped_column(Float, nullable=True)
    error: Mapped[str | None] = mapped_column(Text, nullable=True)
    stats: Mapped[dict] = mapped_column(JSON, default=dict)

    scan: Mapped[Scan] = relationship(back_populates="module_runs")


class RequestRecord(IdMixin, Base):
    __tablename__ = "requests"

    scan_id: Mapped[str] = mapped_column(String(36), ForeignKey("scans.id"), index=True)
    method: Mapped[str] = mapped_column(String(8))
    url: Mapped[str] = mapped_column(Text)
    headers: Mapped[dict] = mapped_column(JSON, default=dict)


class ResponseRecord(IdMixin, Base):
    __tablename__ = "responses"

    scan_id: Mapped[str] = mapped_column(String(36), ForeignKey("scans.id"), index=True)
    request_id: Mapped[str | None] = mapped_column(
        String(36), ForeignKey("requests.id"), nullable=True
    )
    url: Mapped[str] = mapped_column(Text)
    status_code: Mapped[int] = mapped_column(Integer)
    content_type: Mapped[str | None] = mapped_column(String(255), nullable=True)
    content_length: Mapped[int | None] = mapped_column(Integer, nullable=True)
    elapsed_ms: Mapped[float | None] = mapped_column(Float, nullable=True)
    headers: Mapped[dict] = mapped_column(JSON, default=dict)
    redirect_chain: Mapped[list] = mapped_column(JSON, default=list)


class Page(IdMixin, Base):
    __tablename__ = "pages"

    scan_id: Mapped[str] = mapped_column(String(36), ForeignKey("scans.id"), index=True)
    url: Mapped[str] = mapped_column(Text)
    title: Mapped[str | None] = mapped_column(Text, nullable=True)
    status_code: Mapped[int | None] = mapped_column(Integer, nullable=True)
    depth: Mapped[int] = mapped_column(Integer, default=0)
    content_hash: Mapped[str | None] = mapped_column(String(64), nullable=True)
    discovered_from: Mapped[str | None] = mapped_column(Text, nullable=True)


class Asset(IdMixin, Base):
    __tablename__ = "assets"

    scan_id: Mapped[str] = mapped_column(String(36), ForeignKey("scans.id"), index=True)
    asset_type: Mapped[str] = mapped_column(String(32), index=True)
    url: Mapped[str] = mapped_column(Text)
    observation: Mapped[str] = mapped_column(String(16), default="referenced")
    content_hash: Mapped[str | None] = mapped_column(String(64), nullable=True)
    size_bytes: Mapped[int | None] = mapped_column(Integer, nullable=True)
    meta: Mapped[dict] = mapped_column(JSON, default=dict)


class Technology(IdMixin, Base):
    __tablename__ = "technologies"

    scan_id: Mapped[str] = mapped_column(String(36), ForeignKey("scans.id"), index=True)
    name: Mapped[str] = mapped_column(String(128), index=True)
    category: Mapped[str | None] = mapped_column(String(64), nullable=True)
    version: Mapped[str | None] = mapped_column(String(64), nullable=True)
    confidence: Mapped[str] = mapped_column(String(16), default="medium")
    evidence: Mapped[list] = mapped_column(JSON, default=list)


class DnsRecord(IdMixin, Base):
    __tablename__ = "dns_records"

    scan_id: Mapped[str] = mapped_column(String(36), ForeignKey("scans.id"), index=True)
    name: Mapped[str] = mapped_column(String(255), index=True)
    record_type: Mapped[str] = mapped_column(String(16))
    value: Mapped[str] = mapped_column(Text)
    ttl: Mapped[int | None] = mapped_column(Integer, nullable=True)


class IpIntelRecord(IdMixin, Base):
    __tablename__ = "ip_intel"

    scan_id: Mapped[str] = mapped_column(String(36), ForeignKey("scans.id"), index=True)
    edge_cdn: Mapped[str | None] = mapped_column(String(64), nullable=True)
    origin_exposed: Mapped[bool] = mapped_column(default=False)
    ips: Mapped[list] = mapped_column(JSON, default=list)  # list of IpIntel dicts


class Certificate(IdMixin, Base):
    __tablename__ = "certificates"

    scan_id: Mapped[str] = mapped_column(String(36), ForeignKey("scans.id"), index=True)
    subject: Mapped[str | None] = mapped_column(Text, nullable=True)
    issuer: Mapped[str | None] = mapped_column(Text, nullable=True)
    san: Mapped[list] = mapped_column(JSON, default=list)
    not_before: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    not_after: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    details: Mapped[dict] = mapped_column(JSON, default=dict)


class Endpoint(IdMixin, Base):
    __tablename__ = "endpoints"

    scan_id: Mapped[str] = mapped_column(String(36), ForeignKey("scans.id"), index=True)
    url: Mapped[str] = mapped_column(Text)
    method: Mapped[str | None] = mapped_column(String(8), nullable=True)
    kind: Mapped[str] = mapped_column(String(16), default="rest")  # rest|graphql|websocket
    observation: Mapped[str] = mapped_column(String(16), default="potential")
    source: Mapped[str | None] = mapped_column(String(64), nullable=True)
    meta: Mapped[dict] = mapped_column(JSON, default=dict)


class Form(IdMixin, Base):
    __tablename__ = "forms"

    scan_id: Mapped[str] = mapped_column(String(36), ForeignKey("scans.id"), index=True)
    page_url: Mapped[str] = mapped_column(Text)
    action: Mapped[str | None] = mapped_column(Text, nullable=True)
    method: Mapped[str] = mapped_column(String(8), default="get")
    enctype: Mapped[str | None] = mapped_column(String(64), nullable=True)
    inputs: Mapped[list] = mapped_column(JSON, default=list)


class Cookie(IdMixin, Base):
    __tablename__ = "cookies"

    scan_id: Mapped[str] = mapped_column(String(36), ForeignKey("scans.id"), index=True)
    name: Mapped[str] = mapped_column(String(255))
    domain: Mapped[str | None] = mapped_column(String(255), nullable=True)
    path: Mapped[str | None] = mapped_column(String(255), nullable=True)
    secure: Mapped[bool] = mapped_column(default=False)
    http_only: Mapped[bool] = mapped_column(default=False)
    same_site: Mapped[str | None] = mapped_column(String(16), nullable=True)
    attributes: Mapped[dict] = mapped_column(JSON, default=dict)


class FindingRecord(IdMixin, Base):
    __tablename__ = "findings"

    scan_id: Mapped[str] = mapped_column(String(36), ForeignKey("scans.id"), index=True)
    check_id: Mapped[str] = mapped_column(String(128), index=True)
    name: Mapped[str] = mapped_column(Text)
    category: Mapped[str] = mapped_column(String(32), index=True)
    severity: Mapped[str] = mapped_column(String(16), index=True)
    confidence: Mapped[str] = mapped_column(String(16))
    observation: Mapped[str] = mapped_column(String(16), default="observed")
    description: Mapped[str] = mapped_column(Text, default="")
    impact: Mapped[str] = mapped_column(Text, default="")
    recommendation: Mapped[str] = mapped_column(Text, default="")
    module: Mapped[str] = mapped_column(String(64), default="")
    references: Mapped[list] = mapped_column(JSON, default=list)

    scan: Mapped[Scan] = relationship(back_populates="findings")
    evidence: Mapped[list[EvidenceRecord]] = relationship(
        back_populates="finding", cascade="all, delete-orphan"
    )


class ScanEventRecord(IdMixin, Base):
    """One scan-timeline event (G6): discovered / observed / finding / lifecycle."""

    __tablename__ = "scan_events"

    scan_id: Mapped[str] = mapped_column(String(36), ForeignKey("scans.id"), index=True)
    seq: Mapped[int] = mapped_column(Integer)
    ts: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_utcnow)
    kind: Mapped[str] = mapped_column(String(32), index=True)
    module: Mapped[str | None] = mapped_column(String(64), nullable=True)
    label: Mapped[str] = mapped_column(Text)
    data: Mapped[dict] = mapped_column(JSON, default=dict)


class AiAnalysisRecord(IdMixin, Base):
    """A stored AI analysis of a scan (G8); ``result`` embeds cited evidence."""

    __tablename__ = "ai_analyses"

    scan_id: Mapped[str] = mapped_column(String(36), ForeignKey("scans.id"), index=True)
    provider: Mapped[str] = mapped_column(String(32))
    model: Mapped[str] = mapped_column(String(128))
    result: Mapped[dict] = mapped_column(JSON, default=dict)


class EvidenceRecord(IdMixin, Base):
    __tablename__ = "evidence"

    scan_id: Mapped[str] = mapped_column(String(36), ForeignKey("scans.id"), index=True)
    finding_id: Mapped[str | None] = mapped_column(
        String(36), ForeignKey("findings.id"), nullable=True
    )
    source: Mapped[str] = mapped_column(String(64))
    url: Mapped[str | None] = mapped_column(Text, nullable=True)
    description: Mapped[str] = mapped_column(Text)
    data: Mapped[dict] = mapped_column(JSON, default=dict)

    finding: Mapped[FindingRecord | None] = relationship(back_populates="evidence")
