"""v0.2 technology signatures + URL version extraction + Axios vuln."""

from __future__ import annotations

import re

from webrecon.modules.security.rules import known_vulnerable_libraries
from webrecon.modules.technology.fingerprint import extract_url_version, fingerprint
from webrecon.modules.technology.signatures import SIGNATURES


def _names(**kw):
    return {d.name for d in fingerprint(**{"headers": {}, "cookies": [], "html": "",
                                           "script_urls": [], "meta_generator": None, **kw})}


def test_all_signatures_compile() -> None:
    for s in SIGNATURES:
        re.compile(s.pattern)
    assert len(SIGNATURES) >= 100


def test_new_html_signatures() -> None:
    assert "Supabase" in _names(html='<script src="https://x.supabase.co/js"></script>')
    assert "Clerk" in _names(html='<script src="https://clerk.example.dev/clerk-js"></script>')
    assert "Auth0" in _names(html="const a = auth0-spa-js;")
    assert "hCaptcha" in _names(html='<div class="h-captcha"></div>')
    assert "Spring Boot" in _names(html="<h1>Whitelabel Error Page</h1>")
    assert "Chakra UI" in _names(html='<div class="chakra-stack css-1">x</div>')


def test_new_script_signatures() -> None:
    assert "Axios" in _names(script_urls=["https://cdn/axios-1.4.0.min.js"])
    assert "Auth0" in _names(script_urls=["https://cdn/auth0-spa-js.production.js"])
    assert "PocketBase" in _names(script_urls=["https://cdn/pocketbase-0.22.1.js"])


def test_uvicorn_header() -> None:
    assert "Uvicorn" in _names(headers={"Server": "uvicorn"})


def test_vite_asset_url_signature() -> None:
    # Vite/Rollup default output — the real stealx.fr bundle path.
    assert "Vite" in _names(script_urls=["https://x/assets/index-ubP3xnxD.js"])
    # a normal library filename must not be misread as Vite
    assert "Vite" not in _names(script_urls=["https://x/js/jquery.min.js"])


def test_js_content_framework_clues() -> None:
    # framework recovered from JS *content* (survives minification)
    names = _names(js_clues=["React", "Vite"])
    assert "React" in names and "Vite" in names
    # unknown clue names are ignored, not surfaced
    assert "Bogus" not in _names(js_clues=["Bogus"])


def test_js_clue_confidence_is_medium() -> None:
    dets = fingerprint(headers={}, cookies=[], html="", script_urls=[],
                       meta_generator=None, js_clues=["React"])
    react = next(d for d in dets if d.name == "React")
    assert str(react.confidence) == "medium"


def test_url_version_extraction() -> None:
    assert extract_url_version("https://cdn/lib.js?v=1.2.3") == "1.2.3"
    assert extract_url_version("https://cdn/react@18.2.0/umd/react.js") == "18.2.0"
    assert extract_url_version("https://cdn/axios-0.21.0.min.js") == "0.21.0"
    assert extract_url_version("https://cdn/app.js") is None


def test_axios_known_vuln() -> None:
    out = known_vulnerable_libraries([{"name": "Axios", "version": "0.21.0", "confidence": "high"}])
    assert out and out[0].check_id == "technology.vulnerable.axios"
    assert str(out[0].category) == "vulnerability"
    assert "CVE" in out[0].references[0] or "CVE" in out[0].description
