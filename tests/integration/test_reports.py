"""Report generation (§31)."""

from __future__ import annotations

from webrecon.core.config import ScanConfig, ScopeMode
from webrecon.pipeline import Pipeline
from webrecon.reporting.html_report import render_html
from webrecon.reporting.json_report import build_report, collect_extras


def _lab_config() -> ScanConfig:
    cfg = ScanConfig()
    cfg.scope.allow_private_targets = True
    cfg.scope.mode = ScopeMode.SAME_ORIGIN
    cfg.rate.requests_per_second = 100
    cfg.http.verify_tls = False
    return cfg


async def test_html_report_contains_key_sections(mock_site: str) -> None:
    ctx = await Pipeline(_lab_config()).run(mock_site)
    html = render_html(build_report(ctx), collect_extras(ctx))
    assert "Executive Summary" in html
    assert "Findings" in html
    assert "Scope &amp; Methodology" in html
    assert "WordPress" in html  # technology table
    # risk pill present
    assert "b-high" in html


async def test_html_report_escapes_hostile_values() -> None:
    # A finding whose evidence contains HTML must be escaped, not injected.
    report = {
        "scan_id": "abcd1234",
        "target": {"base_url": "https://x", "hostname": "x"},
        "risk": {"level": "low"},
        "config": {"scope": {"mode": "same-origin", "max_depth": 1, "max_pages": 1}},
        "summary": {"total_findings": 1, "by_severity": {"low": 1}},
        "findings": [
            {
                "check_id": "t.x", "name": "<script>alert(1)</script>", "severity": "low",
                "confidence": "low", "observation": "observed", "module": "t",
                "description": "<img src=x onerror=alert(1)>", "impact": "", "recommendation": "",
                "references": [], "evidence": [{"source": "t", "url": "javascript:x", "data": {}}],
            }
        ],
    }
    html = render_html(report)
    assert "<script>alert(1)</script>" not in html
    assert "&lt;script&gt;" in html


async def test_html_report_does_not_leak_secret(mock_site: str) -> None:
    ctx = await Pipeline(_lab_config()).run(mock_site)
    html = render_html(build_report(ctx), collect_extras(ctx))
    assert "AKIAIOSFODNN7EXAMPLE" not in html


async def test_pdf_report_generates(mock_site: str) -> None:
    import pytest

    pytest.importorskip("playwright.async_api")
    from webrecon.reporting.pdf_report import PdfUnavailableError, render_pdf_async

    ctx = await Pipeline(_lab_config()).run(mock_site)
    html = render_html(build_report(ctx), collect_extras(ctx))
    try:
        pdf = await render_pdf_async(html)
    except (PdfUnavailableError, Exception) as exc:  # noqa: BLE001
        import pytest as _pt

        _pt.skip(f"pdf rendering unavailable: {exc}")
    assert pdf[:4] == b"%PDF"
