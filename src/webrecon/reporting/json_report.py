"""Minimal machine-readable JSON report (§31).

A richer HTML/PDF report set lands in Phase P11; this gives the CLI and tests a
stable, complete JSON serialization of a scan now.
"""

from __future__ import annotations

from typing import Any

from ..core.context import ScanContext
from ..core.enums import SEVERITY_ORDER, Severity


def build_report(ctx: ScanContext) -> dict[str, Any]:
    """Serialize a finished scan context into a plain, JSON-safe dict."""
    findings = ctx.all_findings()
    severity_counts: dict[str, int] = {s.value: 0 for s in Severity}
    for f in findings:
        severity_counts[str(f.severity)] += 1

    def sev_key(f: Any) -> int:
        return SEVERITY_ORDER.get(Severity(str(f.severity)), 0)

    risk = ctx.shared.get("risk_summary")
    risk_dict = (
        {
            "level": risk.level,
            "decisive_severity": risk.decisive_severity,
            "by_severity": risk.by_severity,
            "by_confidence": risk.by_confidence,
            "by_category": risk.by_category,
        }
        if risk is not None
        else None
    )

    return {
        "scan_id": ctx.scan_id,
        "target": ctx.target.model_dump(mode="json") if ctx.target else None,
        "risk": risk_dict,
        "config": ctx.config.model_dump(mode="json"),
        "modules": [
            {
                "module": r.module,
                "version": r.version,
                "status": str(r.status),
                "duration_ms": r.duration_ms,
                "error": r.error,
                "stats": r.stats,
                "data": r.data,
            }
            for r in ctx.results.values()
        ],
        "summary": {
            "total_findings": len(findings),
            "by_severity": severity_counts,
            "modules_run": len(ctx.results),
        },
        "findings": [
            f.model_dump(mode="json")
            for f in sorted(findings, key=sev_key, reverse=True)
        ],
    }
