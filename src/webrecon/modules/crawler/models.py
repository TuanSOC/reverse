"""Data shapes produced by the crawler (§7/§24).

Pure Pydantic models so they serialize cleanly into results, storage, and the
relationship graph. ``AssetType``/``Observation`` come from the shared enums so
the whole system agrees on vocabulary.
"""

from __future__ import annotations

from pydantic import Field

from ...core.enums import AssetType, Observation
from ...core.models import WebReconModel


class DiscoveredAsset(WebReconModel):
    url: str
    asset_type: AssetType
    observation: Observation = Observation.REFERENCED
    discovered_from: str | None = None
    attrs: dict = Field(default_factory=dict)


class DiscoveredForm(WebReconModel):
    page_url: str
    action: str | None
    method: str = "get"
    enctype: str | None = None
    inputs: list[dict] = Field(default_factory=list)

    @property
    def looks_sensitive(self) -> bool:
        names = " ".join(
            f"{i.get('name', '')} {i.get('type', '')}".lower() for i in self.inputs
        )
        return any(k in names for k in ("password", "passwd", "otp", "credit", "card"))


class CrawledPage(WebReconModel):
    url: str
    status_code: int | None = None
    title: str | None = None
    depth: int = 0
    content_hash: str | None = None
    content_type: str | None = None
    discovered_from: str | None = None
    canonical: str | None = None
    links: list[str] = Field(default_factory=list)
    meta: dict = Field(default_factory=dict)


class PageExtract(WebReconModel):
    """Everything parsed out of one HTML document."""

    links: list[str] = Field(default_factory=list)
    assets: list[DiscoveredAsset] = Field(default_factory=list)
    forms: list[DiscoveredForm] = Field(default_factory=list)
    title: str | None = None
    canonical: str | None = None
    meta: dict = Field(default_factory=dict)


class CrawlInventory(WebReconModel):
    """Aggregated crawl output published on the context (§24/§25)."""

    pages: list[CrawledPage] = Field(default_factory=list)
    assets: list[DiscoveredAsset] = Field(default_factory=list)
    forms: list[DiscoveredForm] = Field(default_factory=list)
    # Relationship edges for the graph view: (source_url, relation, target_url).
    edges: list[tuple[str, str, str]] = Field(default_factory=list)
    sitemap_urls: list[str] = Field(default_factory=list)
    robots_sitemaps: list[str] = Field(default_factory=list)
    stats: dict = Field(default_factory=dict)
