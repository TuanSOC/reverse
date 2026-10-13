"""Build a report dict + extras from persisted scan data (for `webrecon report`).

Lets reports be regenerated from the database long after a scan, without
re-running it. Shapes match ``build_report``/``collect_extras`` so the same
HTML/PDF renderers apply.
"""

from __future__ import annotations

from typing import Any

from ..api import queries
from ..storage.database import Database
from ..storage.models import Scan
from .intel_sections import intel_from_db


async def build_report_from_db(
    db: Database, scan_id: str
) -> tuple[dict[str, Any], dict[str, Any]] | None:
    overview = await queries.get_overview(db, scan_id)
    if overview is None:
        return None
    findings = await queries.get_findings(db, scan_id)
    endpoints = await queries.get_endpoints(db, scan_id)
    technologies = overview["technologies"]

    async with db.session() as s:
        scan = await s.get(Scan, scan_id)
        scope = (scan.config or {}).get("scope", {}) if scan else {}

    report = {
        "scan_id": scan_id,
        "target": {
            "base_url": overview["target"]["base_url"],
            "hostname": overview["target"]["hostname"],
        },
        "risk": {"level": overview["risk_level"] or "informational"},
        "config": {"scope": scope},
        "summary": {
            "total_findings": overview["total_findings"],
            "by_severity": overview["findings_by_severity"],
        },
        "findings": findings,
        "technologies": technologies,
    }
    pages = await queries.get_pages(db, scan_id)
    assets = await queries.get_assets(db, scan_id)
    extras = {
        "endpoints": endpoints,
        "technologies": technologies,
        "pages_count": len(pages),
        "assets_count": len(assets),
        "ip_intel": overview.get("ip_intel"),
    }
    report["ip_intel"] = overview.get("ip_intel")
    try:
        report["intelligence"] = await intel_from_db(
            db, scan_id, overview=overview, findings=findings, endpoints=endpoints,
            pages=pages, assets=assets)
    except Exception as exc:  # noqa: BLE001 - sections are best-effort; the report is not
        from ..core.logging import get_logger

        get_logger("report").warning("intel sections failed", scan_id=scan_id,
                                     error=f"{type(exc).__name__}: {exc}")
        report["intelligence"] = None
    return report, extras
