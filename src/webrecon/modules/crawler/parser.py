"""HTML extraction — pure, deterministic, and defensive (§7, threat T10).

Parses one HTML document into links, assets, forms, and metadata. All URLs are
resolved to absolute form against the page's final URL. Uses selectolax (fast C
parser); malformed markup never raises — it yields whatever could be parsed.
"""

from __future__ import annotations

import json
from urllib.parse import urljoin

from selectolax.parser import HTMLParser

from ...core.enums import AssetType, Observation
from .models import DiscoveredAsset, DiscoveredForm, PageExtract

# Link-ish rels we treat as navigational links rather than sub-resources.
_LINK_RELS = {"canonical", "alternate", "next", "prev"}
# rel -> asset type for <link> elements.
_LINK_ASSET_RELS = {
    "stylesheet": AssetType.STYLESHEET,
    "icon": AssetType.FAVICON,
    "shortcut icon": AssetType.FAVICON,
    "apple-touch-icon": AssetType.FAVICON,
    "manifest": AssetType.MANIFEST,
    "preload": AssetType.OTHER,
}


def _abs(base: str, href: str | None) -> str | None:
    if not href:
        return None
    href = href.strip()
    if not href or href.startswith(("javascript:", "data:", "mailto:", "tel:", "#")):
        return None
    try:
        return urljoin(base, href)
    except ValueError:
        return None


def parse_html(base_url: str, html: str) -> PageExtract:
    """Extract links/assets/forms/meta from an HTML string."""
    out = PageExtract()
    try:
        tree = HTMLParser(html)
    except Exception:  # noqa: BLE001 - hostile markup must never crash us
        return out

    # Title
    title_node = tree.css_first("title")
    if title_node is not None:
        out.title = (title_node.text() or "").strip() or None

    # <a href>
    for a in tree.css("a[href]"):
        url = _abs(base_url, a.attributes.get("href"))
        if url:
            out.links.append(url)

    # <link rel=...>
    for link in tree.css("link[href]"):
        rel = (link.attributes.get("rel") or "").lower().strip()
        url = _abs(base_url, link.attributes.get("href"))
        if not url:
            continue
        if rel in _LINK_RELS:
            if rel == "canonical":
                out.canonical = url
            out.links.append(url)
        elif rel in _LINK_ASSET_RELS:
            out.assets.append(
                DiscoveredAsset(
                    url=url,
                    asset_type=_LINK_ASSET_RELS[rel],
                    observation=Observation.REFERENCED,
                    discovered_from=base_url,
                    attrs={"rel": rel},
                )
            )

    # <script src>
    for s in tree.css("script[src]"):
        url = _abs(base_url, s.attributes.get("src"))
        if url:
            script_attrs = {
                k: v for k, v in s.attributes.items() if k in ("type", "async", "defer")
            }
            out.assets.append(
                DiscoveredAsset(
                    url=url,
                    asset_type=AssetType.SCRIPT,
                    discovered_from=base_url,
                    attrs=script_attrs,
                )
            )

    # images, iframes, media
    for img in tree.css("img[src]"):
        url = _abs(base_url, img.attributes.get("src"))
        if url:
            out.assets.append(
                DiscoveredAsset(url=url, asset_type=AssetType.IMAGE, discovered_from=base_url)
            )
    for frame in tree.css("iframe[src]"):
        url = _abs(base_url, frame.attributes.get("src"))
        if url:
            out.assets.append(
                DiscoveredAsset(url=url, asset_type=AssetType.IFRAME, discovered_from=base_url)
            )
    for tag in ("video", "audio", "source"):
        for node in tree.css(f"{tag}[src]"):
            url = _abs(base_url, node.attributes.get("src"))
            if url:
                out.assets.append(
                    DiscoveredAsset(url=url, asset_type=AssetType.MEDIA, discovered_from=base_url)
                )

    # forms
    for form in tree.css("form"):
        out.forms.append(_parse_form(base_url, form))

    # metadata: meta tags, opengraph, generator, json-ld
    out.meta = _parse_meta(tree)

    return out


def _parse_form(base_url: str, form) -> DiscoveredForm:
    action = _abs(base_url, form.attributes.get("action")) or base_url
    method = (form.attributes.get("method") or "get").lower()
    enctype = form.attributes.get("enctype")
    inputs: list[dict] = []
    for field in form.css("input, textarea, select"):
        inputs.append(
            {
                "name": field.attributes.get("name"),
                "type": field.attributes.get("type") or field.tag,
                "required": "required" in field.attributes,
            }
        )
    return DiscoveredForm(
        page_url=base_url, action=action, method=method, enctype=enctype, inputs=inputs
    )


def _parse_meta(tree) -> dict:
    meta: dict = {}
    opengraph: dict = {}
    for m in tree.css("meta"):
        name = (m.attributes.get("name") or "").lower()
        prop = (m.attributes.get("property") or "").lower()
        content = m.attributes.get("content")
        if not content:
            continue
        if name == "generator":
            meta["generator"] = content
        elif name == "description":
            meta["description"] = content
        elif prop.startswith("og:"):
            opengraph[prop] = content
    if opengraph:
        meta["opengraph"] = opengraph

    jsonld: list = []
    for node in tree.css('script[type="application/ld+json"]'):
        raw = node.text() or ""
        try:
            jsonld.append(json.loads(raw))
        except (json.JSONDecodeError, ValueError):
            continue
    if jsonld:
        meta["json_ld_count"] = len(jsonld)
    return meta
