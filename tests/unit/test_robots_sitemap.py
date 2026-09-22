"""robots.txt (§16) and sitemap.xml (§17) parsing."""

from __future__ import annotations

from webrecon.modules.crawler.robots import parse_robots
from webrecon.modules.crawler.sitemap import parse_sitemap

ROBOTS = """
# comment
User-agent: *
Disallow: /admin
Disallow: /private
Allow: /admin/public

User-agent: BadBot
Disallow: /

Sitemap: https://ex.com/sitemap.xml
"""


def test_robots_collects_rules_and_sitemaps() -> None:
    r = parse_robots(ROBOTS, user_agent="webrecon")
    assert "/admin" in r.disallow
    assert "/private" in r.disallow
    assert "https://ex.com/sitemap.xml" in r.sitemaps


def test_robots_longest_match_allow_overrides() -> None:
    r = parse_robots(ROBOTS, user_agent="webrecon")
    assert r.is_disallowed("/admin/panel")  # covered by Disallow /admin
    assert not r.is_disallowed("/admin/public/page")  # more specific Allow wins
    assert not r.is_disallowed("/openpath")


def test_sitemap_urlset() -> None:
    xml = (
        '<?xml version="1.0"?>'
        '<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">'
        "<url><loc>https://ex.com/a</loc></url>"
        "<url><loc>https://ex.com/b</loc></url>"
        "</urlset>"
    )
    r = parse_sitemap(xml)
    assert r.urls == ["https://ex.com/a", "https://ex.com/b"]
    assert not r.child_sitemaps


def test_sitemap_index() -> None:
    xml = (
        '<?xml version="1.0"?>'
        '<sitemapindex xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">'
        "<sitemap><loc>https://ex.com/sm1.xml</loc></sitemap>"
        "</sitemapindex>"
    )
    r = parse_sitemap(xml)
    assert r.child_sitemaps == ["https://ex.com/sm1.xml"]
    assert not r.urls


def test_malformed_sitemap_returns_empty() -> None:
    r = parse_sitemap("<not-xml")
    assert r.urls == [] and r.child_sitemaps == []
