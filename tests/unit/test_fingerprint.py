"""Technology fingerprint engine (§10)."""

from __future__ import annotations

from webrecon.core.enums import Confidence
from webrecon.modules.technology.fingerprint import fingerprint


def _by_name(dets):
    return {d.name: d for d in dets}


def test_detects_server_with_version() -> None:
    dets = _by_name(
        fingerprint(
            headers={"Server": "nginx/1.25.3"},
            cookies=[],
            html="",
            script_urls=[],
            meta_generator=None,
        )
    )
    assert "Nginx" in dets
    assert dets["Nginx"].version == "1.25.3"
    assert dets["Nginx"].confidence in (Confidence.HIGH, Confidence.CONFIRMED)


def test_multiple_sources_raise_confidence_and_version_confirms() -> None:
    dets = _by_name(
        fingerprint(
            headers={},
            cookies=[],
            html="<html>/wp-content/themes/x/style.css</html>",
            script_urls=["https://ex.com/wp-content/plugins/a.js"],
            meta_generator="WordPress 6.4.2",
        )
    )
    wp = dets["WordPress"]
    assert wp.version == "6.4.2"
    # meta(version, high) + html + script => confirmed
    assert wp.confidence == Confidence.CONFIRMED
    assert len(wp.sources) >= 2


def test_cookie_signal() -> None:
    dets = _by_name(
        fingerprint(
            headers={},
            cookies=["PHPSESSID=abc; Path=/"],
            html="",
            script_urls=[],
            meta_generator=None,
        )
    )
    assert "PHP" in dets


def test_no_false_positive_on_empty() -> None:
    dets = fingerprint(headers={}, cookies=[], html="", script_urls=[], meta_generator=None)
    assert dets == []
