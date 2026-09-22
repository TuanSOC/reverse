"""Controlled vocabularies used across the whole system.

Kept in one place so the database, API, reports, and modules all agree on the
exact string values. ``Severity`` and ``Confidence`` are deliberately separate
enums (§23): a finding can be high severity / low confidence.
"""

from __future__ import annotations

from enum import Enum


class StrEnum(str, Enum):
    """String enum whose value is the member's lowercase name-ish string.

    (Python 3.11 has ``enum.StrEnum``, but defining our own keeps the value
    explicit and avoids surprises when serializing to JSON/SQLite.)
    """

    def __str__(self) -> str:  # pragma: no cover - trivial
        return str(self.value)


class ModuleStatus(StrEnum):
    """Execution status of a module run."""

    PENDING = "pending"
    RUNNING = "running"
    SUCCESS = "success"
    PARTIAL = "partial"  # produced some output but also hit errors
    FAILED = "failed"
    SKIPPED = "skipped"  # dependency missing or disabled by config
    TIMEOUT = "timeout"
    CANCELLED = "cancelled"


class Severity(StrEnum):
    """Impact if the finding is real. Ordered via :data:`SEVERITY_ORDER`."""

    INFORMATIONAL = "informational"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class Confidence(StrEnum):
    """How certain we are that the finding is accurate — independent of severity."""

    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CONFIRMED = "confirmed"


class Observation(StrEnum):
    """Provenance/certainty of an asset or endpoint (§19).

    Never assert an endpoint *exists* just because a string appears in JS.
    """

    OBSERVED = "observed"  # seen in an actual request/response
    REFERENCED = "referenced"  # linked/referenced in HTML, JS, sitemap, etc.
    POTENTIAL = "potential"  # a bare string match; existence unproven


class AssetType(StrEnum):
    """Kinds of discovered assets tracked in the inventory (§24)."""

    PAGE = "page"
    SCRIPT = "script"
    STYLESHEET = "stylesheet"
    IMAGE = "image"
    FONT = "font"
    MEDIA = "media"
    DOCUMENT = "document"
    IFRAME = "iframe"
    FAVICON = "favicon"
    MANIFEST = "manifest"
    SOURCEMAP = "sourcemap"
    OTHER = "other"


class FindingCategory(StrEnum):
    """Top-level grouping for security findings (§21)."""

    TRANSPORT = "transport"  # TLS/HTTPS
    HEADERS = "headers"
    COOKIES = "cookies"
    CORS = "cors"
    CONTENT = "content"  # mixed content, directory listing, info disclosure
    DNS = "dns"
    EXPOSURE = "exposure"  # source maps, robots leaks, debug endpoints
    TECHNOLOGY = "technology"  # outdated/vulnerable fingerprint
    CONFIGURATION = "configuration"
    INFORMATIONAL = "informational"


SEVERITY_ORDER: dict[Severity, int] = {
    Severity.INFORMATIONAL: 0,
    Severity.LOW: 1,
    Severity.MEDIUM: 2,
    Severity.HIGH: 3,
    Severity.CRITICAL: 4,
}

CONFIDENCE_ORDER: dict[Confidence, int] = {
    Confidence.LOW: 0,
    Confidence.MEDIUM: 1,
    Confidence.HIGH: 2,
    Confidence.CONFIRMED: 3,
}
