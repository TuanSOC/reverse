"""Core schema invariants (§22/§23)."""

from __future__ import annotations

import time

import pytest
from pydantic import ValidationError

from webrecon.core.enums import (
    Confidence,
    FindingCategory,
    ModuleStatus,
    Observation,
    Severity,
)
from webrecon.core.models import Evidence, Finding, ModuleResult


def _evidence() -> Evidence:
    return Evidence(source="test", description="observed thing", data={"k": "v"})


def test_finding_requires_evidence() -> None:
    with pytest.raises(ValidationError):
        Finding(
            check_id="x.y",
            name="n",
            category=FindingCategory.HEADERS,
            severity=Severity.MEDIUM,
            confidence=Confidence.HIGH,
            description="d",
            evidence=[],
        )


def test_finding_severity_and_confidence_are_independent() -> None:
    f = Finding(
        check_id="headers.hsts.missing",
        name="Missing HSTS",
        category=FindingCategory.HEADERS,
        severity=Severity.HIGH,
        confidence=Confidence.LOW,  # high severity, low confidence must be expressible
        description="d",
        evidence=[_evidence()],
    )
    assert f.severity == Severity.HIGH
    assert f.confidence == Confidence.LOW
    assert f.observation == Observation.OBSERVED


def test_finding_rejects_unknown_fields() -> None:
    with pytest.raises(ValidationError):
        Finding(
            check_id="a.b",
            name="n",
            category=FindingCategory.HEADERS,
            severity=Severity.LOW,
            confidence=Confidence.LOW,
            description="d",
            evidence=[_evidence()],
            bogus="nope",
        )


def test_module_result_timing() -> None:
    r = ModuleResult(module="demo", version="1.2.3")
    assert r.status == ModuleStatus.PENDING
    r.mark_started()
    assert r.status == ModuleStatus.RUNNING
    time.sleep(0.005)
    r.mark_finished(ModuleStatus.SUCCESS)
    assert r.status == ModuleStatus.SUCCESS
    assert r.duration_ms is not None and r.duration_ms >= 0
