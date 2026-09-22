"""HTML extraction (§7)."""

from __future__ import annotations

from webrecon.core.enums import AssetType
from webrecon.modules.crawler.parser import parse_html

SAMPLE = """<!doctype html>
<html><head>
<title>  Home  </title>
<meta name="generator" content="Acme CMS 2.1">
<meta name="description" content="desc">
<meta property="og:title" content="OG Home">
<link rel="canonical" href="https://ex.com/home">
<link rel="stylesheet" href="/css/site.css">
<link rel="icon" href="/favicon.ico">
<link rel="manifest" href="/app.webmanifest">
<script src="/js/app.js" defer></script>
<script type="application/ld+json">{"@type":"WebSite"}</script>
</head><body>
<a href="/about">About</a>
<a href="https://other.com/x">Ext</a>
<a href="javascript:void(0)">JS</a>
<a href="#frag">Frag</a>
<img src="/img/logo.png">
<iframe src="/embed"></iframe>
<form action="/login" method="post">
  <input name="user" type="text">
  <input name="password" type="password">
</form>
</body></html>"""


def test_extracts_links_and_ignores_non_navigational() -> None:
    e = parse_html("https://ex.com/", SAMPLE)
    assert "https://ex.com/about" in e.links
    assert "https://other.com/x" in e.links
    # javascript:, #fragment are dropped
    assert all("javascript:" not in link for link in e.links)
    assert all("#frag" not in link for link in e.links)


def test_extracts_assets_with_types() -> None:
    e = parse_html("https://ex.com/", SAMPLE)
    by_type = {a.asset_type for a in e.assets}
    assert AssetType.SCRIPT in by_type
    assert AssetType.STYLESHEET in by_type
    assert AssetType.FAVICON in by_type
    assert AssetType.MANIFEST in by_type
    assert AssetType.IMAGE in by_type
    assert AssetType.IFRAME in by_type
    urls = {a.url for a in e.assets}
    assert "https://ex.com/js/app.js" in urls


def test_metadata_title_canonical_opengraph() -> None:
    e = parse_html("https://ex.com/", SAMPLE)
    assert e.title == "Home"
    assert e.canonical == "https://ex.com/home"
    assert e.meta["generator"] == "Acme CMS 2.1"
    assert e.meta["opengraph"]["og:title"] == "OG Home"
    assert e.meta["json_ld_count"] == 1


def test_form_and_sensitivity_detection() -> None:
    e = parse_html("https://ex.com/", SAMPLE)
    assert len(e.forms) == 1
    form = e.forms[0]
    assert form.method == "post"
    assert form.action == "https://ex.com/login"
    assert form.looks_sensitive  # has a password field


def test_malformed_html_does_not_raise() -> None:
    e = parse_html("https://ex.com/", "<html><a href=></a><form><input")
    assert isinstance(e.links, list)
