"""Pydantic schemas shared by every module.

These are the wire/records formats — the same shapes flow from a module's
``run()`` into storage, the API, and reports. Two rules are encoded here so no
module can bypass them:

* every :class:`Finding` carries independent ``severity`` and ``confidence``,
  plus at least one :class:`Evidence` item;
* every endpoint/finding-ish record carries an :class:`Observation` provenance.
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime

from pydantic import BaseModel, ConfigDict, Field, field_validator

from .enums import (
    Confidence,
    FindingCategory,
    ModuleStatus,
    Observation,
    Severity,
)


def _uuid() -> str:
    return str(uuid.uuid4())


def utcnow() -> datetime:
    """Timezone-aware UTC now. Single source so timestamps are consistent."""
    return datetime.now(UTC)


class WebReconModel(BaseModel):
    """Base model: forbids unknown fields, serializes enums by value."""

    model_config = ConfigDict(
        extra="forbid",
        use_enum_values=False,
        validate_assignment=True,
    )


class Evidence(WebReconModel):
    """A concrete, inspectable proof backing a finding or asset (§22).

    Never fabricate evidence: ``data`` must contain the actual observed value
    (header contents, cert fields, matched string + offset, etc.).
    """

    id: str = Field(default_factory=_uuid)
    source: str = Field(description="Module that produced this evidence, e.g. 'tls'.")
    url: str | None = Field(default=None, description="URL the evidence was observed at.")
    description: str
    data: dict = Field(default_factory=dict, description="Raw observed values.")
    created_at: datetime = Field(default_factory=utcnow)


class Finding(WebReconModel):
    """A security-relevant observation with impact and remediation (§21/§23).

    ``severity`` (impact if real) and ``confidence`` (certainty it's real) are
    independent. At least one evidence item is required.
    """

    id: str = Field(default_factory=_uuid)
    check_id: str = Field(description="Stable id of the check, e.g. 'headers.hsts.missing'.")
    name: str
    category: FindingCategory
    severity: Severity
    confidence: Confidence
    observation: Observation = Observation.OBSERVED
    description: str
    impact: str = ""
    recommendation: str = ""
    references: list[str] = Field(default_factory=list)
    evidence: list[Evidence] = Field(default_factory=list)
    module: str = ""
    created_at: datetime = Field(default_factory=utcnow)

    @field_validator("evidence")
    @classmethod
    def _require_evidence(cls, v: list[Evidence]) -> list[Evidence]:
        if not v:
            raise ValueError("a Finding must carry at least one Evidence item")
        return v


class ModuleResult(WebReconModel):
    """Uniform result envelope returned by every module (§2).

    The pipeline builds this even when a module raises — a crash becomes a
    ``FAILED`` result, never an aborted scan.
    """

    module: str
    version: str = "0.0.0"
    status: ModuleStatus = ModuleStatus.PENDING
    started_at: datetime | None = None
    finished_at: datetime | None = None
    duration_ms: float | None = None
    timed_out: bool = False
    error: str | None = None
    findings: list[Finding] = Field(default_factory=list)
    evidence: list[Evidence] = Field(default_factory=list)
    # Module-specific structured output (assets, dns records, tech, …). Kept as
    # a free dict here; typed per-module models live in each module package.
    data: dict = Field(default_factory=dict)
    stats: dict = Field(default_factory=dict)

    def mark_started(self) -> None:
        self.started_at = utcnow()
        self.status = ModuleStatus.RUNNING

    def mark_finished(self, status: ModuleStatus) -> None:
        self.finished_at = utcnow()
        self.status = status
        if self.started_at is not None and self.finished_at is not None:
            self.duration_ms = (self.finished_at - self.started_at).total_seconds() * 1000.0
