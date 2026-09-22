"""PDF report (§31) — renders the HTML report to PDF via headless Chromium.

Reuses the Playwright browser already required for browser mode, so no extra
native dependency (e.g. wkhtmltopdf/weasyprint) is needed. The HTML is loaded
via ``set_content`` (no network), so the PDF is a faithful, self-contained copy
of the HTML report.
"""

from __future__ import annotations


class PdfUnavailableError(RuntimeError):
    """Raised when Playwright/Chromium is not available for PDF rendering."""


async def render_pdf_async(html: str) -> bytes:
    try:
        from playwright.async_api import async_playwright
    except ImportError as exc:  # pragma: no cover
        raise PdfUnavailableError("playwright not installed (pip install -e '.[browser]')") from exc

    async with async_playwright() as pw:
        browser = await pw.chromium.launch(headless=True)
        try:
            page = await browser.new_page()
            await page.set_content(html, wait_until="load")
            return await page.pdf(format="A4", print_background=True)
        finally:
            await browser.close()


def render_pdf(html: str) -> bytes:
    """Sync wrapper. Must not be called from within a running event loop."""
    import asyncio

    return asyncio.run(render_pdf_async(html))
