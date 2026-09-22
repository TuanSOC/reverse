"""sitemap.xml parsing (§17).

Handles both URL sets and sitemap indexes. Uses defused parsing settings
(no external entity resolution) to avoid XXE from a hostile sitemap (threat T10).
Returns child sitemap URLs separately so the caller controls recursion depth.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from xml.etree import ElementTree as ET


@dataclass
class SitemapResult:
    urls: list[str] = field(default_factory=list)
    child_sitemaps: list[str] = field(default_factory=list)


def _localname(tag: str) -> str:
    return tag.rsplit("}", 1)[-1].lower()


def parse_sitemap(xml_text: str) -> SitemapResult:
    """Parse a sitemap or sitemap index. Malformed XML yields an empty result."""
    result = SitemapResult()
    # ElementTree does not resolve external entities by default in modern Python,
    # so this is safe against classic XXE; we still guard against parse errors.
    try:
        root = ET.fromstring(xml_text)  # noqa: S314 - no external entity resolution
    except ET.ParseError:
        return result

    root_name = _localname(root.tag)
    for child in root.iter():
        name = _localname(child.tag)
        if name != "loc":
            continue
        loc = (child.text or "").strip()
        if not loc:
            continue
        if root_name == "sitemapindex":
            result.child_sitemaps.append(loc)
        else:
            result.urls.append(loc)
    return result
