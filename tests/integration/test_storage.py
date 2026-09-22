"""Storage round-trip against an in-memory SQLite database (§27)."""

from __future__ import annotations

import pytest
from sqlalchemy import select

from webrecon.storage.database import Database
from webrecon.storage.models import (
    EvidenceRecord,
    FindingRecord,
    Scan,
    Target,
)


@pytest.fixture
async def db() -> Database:
    database = Database("sqlite+aiosqlite:///:memory:")
    await database.create_all()
    try:
        yield database
    finally:
        await database.dispose()


async def test_schema_creates_all_tables(db: Database) -> None:
    from webrecon.storage.models import Base

    expected = {
        "targets", "scans", "module_runs", "requests", "responses", "pages",
        "assets", "technologies", "dns_records", "certificates", "endpoints",
        "forms", "cookies", "findings", "evidence",
    }
    assert expected <= set(Base.metadata.tables)


async def test_target_scan_finding_evidence_roundtrip(db: Database) -> None:
    async with db.session() as s:
        target = Target(
            input_url="https://example.com",
            scheme="https",
            hostname="example.com",
            port=443,
            base_url="https://example.com",
        )
        s.add(target)
        await s.flush()
        scan = Scan(target_id=target.id, status="success")
        s.add(scan)
        await s.flush()
        finding = FindingRecord(
            scan_id=scan.id,
            check_id="headers.hsts.missing",
            name="Missing HSTS",
            category="headers",
            severity="medium",
            confidence="high",
            description="d",
        )
        s.add(finding)
        await s.flush()
        s.add(
            EvidenceRecord(
                scan_id=scan.id,
                finding_id=finding.id,
                source="headers",
                url="https://example.com",
                description="header absent",
                data={"header": "Strict-Transport-Security", "value": None},
            )
        )

    async with db.session() as s:
        rows = (await s.execute(select(FindingRecord))).scalars().all()
        assert len(rows) == 1
        assert rows[0].check_id == "headers.hsts.missing"
        ev = (await s.execute(select(EvidenceRecord))).scalars().all()
        assert len(ev) == 1
        assert ev[0].data["header"] == "Strict-Transport-Security"
