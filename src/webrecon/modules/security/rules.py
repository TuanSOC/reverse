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


def content_disclosure(disc) -> list[Finding]:
    """Findings from content scanned during crawl/JS analysis (emails/IPs/traces)."""
    from ..disclosure import mask_email

    out: list[Finding] = []
    if disc.has_stack_trace:
        out.append(_finding(
            "content.disclosure.stack_trace", "Stack trace / error details exposed",
            FindingCategory.EXPOSURE, Severity.MEDIUM, Confidence.MEDIUM,
            "A page or script contains a stack trace or verbose error signature.",
            "Leaks framework internals, file paths, and query fragments useful to an attacker.",
            "Disable debug/verbose errors in production; return generic error pages.",
            Evidence(source="security", url=None,
                     description="Error/stack-trace signature", data={}),
        ))
    if disc.internal_hosts:
        out.append(_finding(
            "content.disclosure.internal_host", "Internal hostnames exposed",
            FindingCategory.EXPOSURE, Severity.LOW, Confidence.MEDIUM,
            "Internal hostnames (.local/.internal/.corp) appear in public content.",
            "Reveals internal network naming useful for lateral movement/targeting.",
            "Remove internal hostnames from public pages/scripts.",
            Evidence(source="security", url=None, description="Internal hostnames",
                     data={"hosts": sorted(disc.internal_hosts)[:20]}),
        ))
    if disc.private_ips:
        out.append(_finding(
            "content.disclosure.private_ip", "Private IP addresses exposed",
            FindingCategory.EXPOSURE, Severity.LOW, Confidence.MEDIUM,
            "Private/internal IP addresses appear in public content.",
            "Leaks internal network layout.",
            "Remove internal IPs from public pages/scripts.",
            Evidence(source="security", url=None, description="Private IPs",
                     data={"ips": sorted(disc.private_ips)[:20]}),
        ))
    if disc.emails:
        out.append(_finding(
            "content.disclosure.emails", f"{len(disc.emails)} email address(es) exposed",
            FindingCategory.INFORMATIONAL, Severity.INFORMATIONAL, Confidence.HIGH,
            "Email addresses are published in page/script content.",
            "May be harvested for spam/phishing (often intentional for contact pages).",
            "Consider obfuscation or a contact form if these are not meant to be public.",
            Evidence(source="security", url=None, description="Emails (masked)",
                     data={"sample": [mask_email(e) for e in sorted(disc.emails)[:15]],
                           "count": len(disc.emails)}),
        ))
    return out


def known_vulnerable_libraries(detections: list[dict]) -> list[Finding]:
    """Flag detected libraries whose version is below a known-fixed version."""
    from .vulndb import KNOWN_VULNS

    findings: list[Finding] = []
    for det in detections:
        name = det.get("name")
        version = det.get("version")
        conf = det.get("confidence")
        advisories = KNOWN_VULNS.get(name) if name else None
        if not advisories or not version or conf not in ("medium", "high", "confirmed"):
            continue
        detected = _parse_version(version)
        if not detected:
            continue
        # Report the most relevant (highest fixed_in that the version is below).
        hit = None
        for adv in advisories:
            if detected < adv.fixed_in:
                if hit is None or adv.fixed_in > hit.fixed_in:
                    hit = adv
        if hit is None:
            continue
        finding_conf = Confidence.MEDIUM if conf in ("high", "confirmed") else Confidence.LOW
        findings.append(
            Finding(
                check_id="technology.vulnerable."
                + str(name).lower().replace(" ", "_").replace(".", ""),
                name=f"Known-vulnerable {name} {version}",
                category=FindingCategory.TECHNOLOGY, severity=hit.severity, confidence=finding_conf,
                observation=Observation.REFERENCED, module="security",
                description=(f"{name} {version} is below "
                            f"{'.'.join(map(str, hit.fixed_in))}: {hit.summary}"),
                impact="The version in use has publicly documented vulnerabilities.",
                recommendation=f"Upgrade {name} to {'.'.join(map(str, hit.fixed_in))} or later.",
                references=[hit.reference],
                evidence=[Evidence(source="security", url=None, description="Vulnerable version",
                                   data={"technology": name, "version": version,
                                         "fixed_in": ".".join(map(str, hit.fixed_in))})],
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
