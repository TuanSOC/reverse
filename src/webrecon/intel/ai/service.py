"""Run, persist and fetch AI analyses of stored scans."""

from __future__ import annotations

from typing import Any

from sqlalchemy import select

from ...storage.database import Database
from ...storage.models import AiAnalysisRecord
from .analyzers import AiAnalyzer, get_analyzer
from .context import build_analysis_context


async def analyze_scan(
    db: Database, scan_id: str, *, provider: str | None = None,
    analyzer: AiAnalyzer | None = None,
) -> dict[str, Any] | None:
    """Analyze a stored scan and save the result; ``None`` if the scan is unknown.

    Raises :class:`~.analyzers.AiError` on provider failure (nothing is saved).
    """
    ctx = await build_analysis_context(db, scan_id)
    if ctx is None:
        return None
    analyzer = analyzer or get_analyzer(provider)
    analysis = await analyzer.analyze(ctx)
    result = analysis.to_dict(ctx)
    async with db.session() as s:
        s.add(AiAnalysisRecord(scan_id=scan_id, provider=analysis.provider,
                               model=analysis.model, result=result))
    return result


async def latest_analysis(db: Database, scan_id: str) -> dict[str, Any] | None:
    async with db.session() as s:
        row = (
            await s.execute(
                select(AiAnalysisRecord)
                .where(AiAnalysisRecord.scan_id == scan_id)
                .order_by(AiAnalysisRecord.created_at.desc())
                .limit(1)
            )
        ).scalars().first()
        return dict(row.result) if row is not None else None
