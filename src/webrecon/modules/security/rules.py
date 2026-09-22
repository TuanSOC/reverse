"""Cross-module security rules (§21).

Pure functions that derive findings requiring signals from more than one module
(so no single module owns them): mixed content, outdated technology (only where
a reliable version exists), and directory-listing indicators. Each returns a
list of Findings with evidence — never a bare assertion.
"""

from __future__ import annotations

from ...core.enums import (
    Confidence,
    FindingCategory,
    Observation,
    Severity,
)
from ...core.models import Evidence, Finding
from ...core.urls import parse_url

# Minimum non-EOL versions for a few widely-fingerprinted components. Kept
# small and conservative; only fires when a version is actually detected.
MIN_SAFE_VERSIONS: dict[str, tuple[int, ...]] = {
    "jQuery": (3, 0, 0),
    "PHP": (7, 4, 0),
    "Bootstrap": (4, 0, 0),
}


def _parse_version(v: str) -> tuple[int, ...]:
    parts = []
    for chunk in v.split("."):
        num = "".join(ch for ch in chunk if ch.isdigit())
        if not num:
            break
        parts.append(int(num))
    return tuple(parts)


def _finding(check_id, name, category, severity, confidence, desc, impact, rec, ev):
    return Finding(
        check_id=check_id, name=name, category=category, severity=severity,
        confidence=confidence, observation=Observation.OBSERVED, module="security",
        description=desc, impact=impact, recommendation=rec, evidence=[ev],
    )


def mixed_content(final_url: str, asset_urls: list[str]) -> list[Finding]:
    """HTTPS page loading http:// sub-resources (§21)."""
    try:
        if parse_url(final_url).scheme != "https":
            return []
    except ValueError:
        return []
    http_assets = [u for u in asset_urls if u.lower().startswith("http://")]
    if not http_assets:
        return []
    return [
        _finding(
            "content.mixed_content", "Mixed content on HTTPS page",
            FindingCategory.CONTENT, Severity.MEDIUM, Confidence.HIGH,
            "An HTTPS page references sub-resources over plain HTTP.",
            "Mixed content can be blocked or tampered with, weakening page integrity.",
            "Serve all sub-resources over HTTPS.",
            Evidence(
                source="security", url=final_url, description="HTTP sub-resources on HTTPS page",
                data={"count": len(http_assets), "sample": http_assets[:10]},
            ),
        )
    ]


def outdated_technology(detections: list[dict]) -> list[Finding]:
    """Flag detected components older than a known-safe minimum (§21)."""
    findings: list[Finding] = []
    for det in detections:
        name = det.get("name")
        version = det.get("version")
        conf = det.get("confidence")
        if not name or not version or name not in MIN_SAFE_VERSIONS:
            continue
        # Require at least a medium-confidence detection carrying a version.
        if conf not in ("medium", "high", "confirmed"):
            continue
        # Scale the finding's confidence to how sure the detection was.
        finding_conf = Confidence.MEDIUM if conf in ("high", "confirmed") else Confidence.LOW
        detected = _parse_version(version)
        minimum = MIN_SAFE_VERSIONS[name]
        if detected and detected < minimum:
            findings.append(
                _finding(
                    f"technology.outdated.{name.lower()}",
                    f"Outdated {name} ({version})",
                    FindingCategory.TECHNOLOGY, Severity.MEDIUM, finding_conf,
                    f"{name} {version} is older than recommended "
                    f"({'.'.join(map(str, minimum))}).",
                    "Old components may contain known, publicly documented vulnerabilities.",
                    f"Upgrade {name} to a supported version.",
                    Evidence(
                        source="security", url=None, description="Outdated component",
                        data={"technology": name, "version": version, "min_safe":
                              ".".join(map(str, minimum))},
                    ),
                )
            )
    return findings


def directory_listing(page_titles: list[tuple[str, str]]) -> list[Finding]:
    """Detect auto-index pages via their 'Index of /' title (url, title pairs)."""
    findings: list[Finding] = []
    for url, title in page_titles:
        if title and title.strip().lower().startswith("index of "):
            findings.append(
                _finding(
                    "content.directory_listing", "Directory listing enabled",
                    FindingCategory.EXPOSURE, Severity.LOW, Confidence.HIGH,
                    f"The server returns an auto-generated directory index at {url}.",
                    "Directory listings can expose files not meant to be discoverable.",
                    "Disable auto-indexing (e.g. Options -Indexes / autoindex off).",
                    Evidence(
                        source="security", url=url, description="Directory index page",
                        data={"title": title},
                    ),
                )
            )
    return findings
