"""Risk classification (§23).

Turns the full set of findings into a deterministic, rule-based risk summary.
The overall level is the highest severity present among findings that carry at
least ``medium`` confidence — so a high-severity but low-confidence finding does
not by itself escalate the whole scan (it is still reported, just not decisive).
"""

from __future__ import annotations

from dataclasses import dataclass, field

from ...core.enums import (
    CONFIDENCE_ORDER,
    SEVERITY_ORDER,
    Confidence,
    Severity,
)
from ...core.models import Finding

_LEVEL_BY_SEVERITY = {
    Severity.CRITICAL: "critical",
    Severity.HIGH: "high",
    Severity.MEDIUM: "medium",
    Severity.LOW: "low",
    Severity.INFORMATIONAL: "informational",
}


@dataclass
class RiskSummary:
    level: str = "informational"
    total: int = 0
    by_severity: dict[str, int] = field(default_factory=dict)
    by_confidence: dict[str, int] = field(default_factory=dict)
    by_category: dict[str, int] = field(default_factory=dict)
    decisive_severity: str | None = None


def classify(findings: list[Finding]) -> RiskSummary:
    summary = RiskSummary(total=len(findings))
    summary.by_severity = {s.value: 0 for s in Severity}
    summary.by_confidence = {c.value: 0 for c in Confidence}

    highest = Severity.INFORMATIONAL
    for f in findings:
        sev = Severity(str(f.severity))
        conf = Confidence(str(f.confidence))
        summary.by_severity[sev.value] += 1
        summary.by_confidence[conf.value] += 1
        cat = str(f.category)
        summary.by_category[cat] = summary.by_category.get(cat, 0) + 1
        # Only findings with >= medium confidence set the decisive level.
        if CONFIDENCE_ORDER[conf] >= CONFIDENCE_ORDER[Confidence.MEDIUM]:
            if SEVERITY_ORDER[sev] > SEVERITY_ORDER[highest]:
                highest = sev

    summary.decisive_severity = highest.value
    summary.level = _LEVEL_BY_SEVERITY[highest]
    return summary
