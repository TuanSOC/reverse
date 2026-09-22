"""Risk classification + cross-module rules (§21/§23)."""

from __future__ import annotations

from webrecon.core.enums import (
    Confidence,
    FindingCategory,
    Observation,
    Severity,
)
from webrecon.core.models import Evidence, Finding
from webrecon.modules.security import rules
from webrecon.modules.security.risk import classify


def _f(sev: Severity, conf: Confidence) -> Finding:
    return Finding(
        check_id="x.y", name="n", category=FindingCategory.HEADERS,
        severity=sev, confidence=conf, description="d",
        evidence=[Evidence(source="t", description="e")],
    )


def test_level_uses_highest_medium_plus_confidence() -> None:
    findings = [_f(Severity.HIGH, Confidence.LOW), _f(Severity.MEDIUM, Confidence.HIGH)]
    summary = classify(findings)
    # HIGH is low-confidence -> not decisive; MEDIUM/high is -> level medium.
    assert summary.level == "medium"
    assert summary.decisive_severity == "medium"


def test_high_confidence_high_severity_escalates() -> None:
    summary = classify([_f(Severity.HIGH, Confidence.HIGH)])
    assert summary.level == "high"


def test_empty_is_informational() -> None:
    assert classify([]).level == "informational"


def test_mixed_content_only_on_https() -> None:
    assert rules.mixed_content("http://ex.com", ["http://ex.com/a.js"]) == []
    out = rules.mixed_content("https://ex.com", ["http://ex.com/a.js", "https://ex.com/b.js"])
    assert len(out) == 1
    assert out[0].check_id == "content.mixed_content"


def test_outdated_technology_needs_version_and_confidence() -> None:
    assert rules.outdated_technology(
        [{"name": "jQuery", "version": None, "confidence": "high"}]
    ) == []
    # low confidence is ignored
    assert rules.outdated_technology(
        [{"name": "jQuery", "version": "1.12.4", "confidence": "low"}]
    ) == []
    out = rules.outdated_technology(
        [{"name": "jQuery", "version": "1.12.4", "confidence": "confirmed"}]
    )
    assert out and out[0].check_id == "technology.outdated.jquery"
    # up-to-date version does not fire
    assert rules.outdated_technology(
        [{"name": "jQuery", "version": "3.7.1", "confidence": "confirmed"}]
    ) == []


def test_directory_listing() -> None:
    out = rules.directory_listing([("https://ex.com/files/", "Index of /files")])
    assert out and out[0].check_id == "content.directory_listing"
    assert rules.directory_listing([("https://ex.com/", "Home")]) == []


def test_finding_observation_is_observed() -> None:
    out = rules.mixed_content("https://ex.com", ["http://ex.com/a.js"])
    assert out[0].observation == Observation.OBSERVED
