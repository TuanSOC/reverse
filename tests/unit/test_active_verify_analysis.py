"""Unit tests for active_verify probe-building + response analysis (pure)."""

from __future__ import annotations

from webrecon.modules.active_verify.analysis import (
    REDIRECT_CANARY_HOST,
    REDIRECT_VARIANTS,
    build_redirect_probe,
    build_xss_probe,
    effective_redirect_host,
    redirect_confirmed,
    xss_canary,
    xss_reflected,
)


def test_build_redirect_probe_sets_canary() -> None:
    probe = build_redirect_probe("https://x.com/go?next=/home&id=5", "next")
    assert REDIRECT_CANARY_HOST in probe
    assert "id=5" in probe  # other params preserved


def test_build_redirect_probe_adds_missing_param() -> None:
    probe = build_redirect_probe("https://x.com/go", "url")
    assert "url=" in probe and REDIRECT_CANARY_HOST in probe


def test_variants_cover_bypass_families() -> None:
    labels = {label for label, _ in REDIRECT_VARIANTS}
    assert {"absolute", "scheme_relative", "backslash", "userinfo",
            "double_encoded"} <= labels


def test_effective_redirect_host_bypass_forms() -> None:
    c = REDIRECT_CANARY_HOST
    assert effective_redirect_host(f"https://{c}/") == c
    assert effective_redirect_host(f"//{c}/path") == c          # scheme-relative
    assert effective_redirect_host(f"/\\{c}/") == c             # backslash → slash
    assert effective_redirect_host(f"https://trusted@{c}/") == c  # userinfo trick
    assert effective_redirect_host(f"%2f%2f{c}%2f") == c        # encoded //
    assert effective_redirect_host("/home") is None             # same-site relative


def test_redirect_confirmed_true_on_3xx_to_canary() -> None:
    assert redirect_confirmed(302, f"https://{REDIRECT_CANARY_HOST}/") is True
    assert redirect_confirmed(301, f"//{REDIRECT_CANARY_HOST}/x") is True


def test_redirect_not_confirmed() -> None:
    assert redirect_confirmed(200, f"https://{REDIRECT_CANARY_HOST}/") is False  # not 3xx
    assert redirect_confirmed(302, "https://x.com/home") is False  # own site
    assert redirect_confirmed(302, "/home") is False  # same-site relative path
    assert redirect_confirmed(302, None) is False


def test_xss_canary_unique_per_param() -> None:
    a = xss_canary("https://x.com/p", "q")
    b = xss_canary("https://x.com/p", "r")
    assert a != b
    assert a.endswith("<xss>") and a.startswith("wrx")


def test_build_xss_probe_injects_canary() -> None:
    probe = build_xss_probe("https://x.com/s?q=hi", "q")
    assert xss_canary("https://x.com/s?q=hi", "q") in _unquote(probe)


def test_xss_reflected_unencoded_in_html() -> None:
    url, param = "https://x.com/s?q=1", "q"
    canary = xss_canary(url, param)
    assert xss_reflected(f"<div>{canary}</div>", "text/html", url, param) is True


def test_xss_not_reflected_when_encoded() -> None:
    url, param = "https://x.com/s?q=1", "q"
    canary = xss_canary(url, param)
    encoded = canary.replace("<", "&lt;").replace(">", "&gt;")
    assert xss_reflected(f"<div>{encoded}</div>", "text/html", url, param) is False


def test_xss_not_reflected_on_non_html() -> None:
    url, param = "https://x.com/s?q=1", "q"
    canary = xss_canary(url, param)
    assert xss_reflected(canary, "application/json", url, param) is False


def _unquote(s: str) -> str:
    from urllib.parse import unquote
    return unquote(s)
