"""Browser mode via Playwright (§20).

Renders the target in a headless Chromium, observes the network (XHR/fetch and
WebSocket), collects dynamically loaded assets, and captures a screenshot. This
is the only place target JavaScript executes — inside the browser sandbox, never
in the tool process (threat T5).

Scope is enforced *inside the browser too*: a request-router aborts any HTTP(S)
request whose URL is out of scope, so rendering cannot pull the browser to
third-party or internal hosts. The module only runs when ``browser_mode`` is
enabled; otherwise it skips immediately (so it is cheap to keep in the pipeline).
"""

from __future__ import annotations

from pathlib import Path

from ...core.enums import ModuleStatus, Observation
from ...core.models import Evidence, ModuleResult
from ...core.module import ScannerModule
from ...core.registry import default_registry

# Key under which browser-observed endpoints are published for API discovery.
BROWSER_ENDPOINTS_KEY = "browser_endpoints"


@default_registry.register
class BrowserModule(ScannerModule):
    name = "browser"
    version = "0.1.0"
    requires = ("scope",)
    timeout_seconds = 90.0
    description = "Headless render + network observation (opt-in via browser_mode)."

    async def run(self, ctx) -> ModuleResult:  # type: ignore[override]
        result = self.new_result()
        result.mark_started()
        log = ctx.bind_logger(self.name)

        if not ctx.config.browser_mode:
            result.data = {"skipped": "browser_mode disabled"}
            result.mark_finished(ModuleStatus.SKIPPED)
            return result
        if ctx.target is None or ctx.scope is None:
            result.error = "target/scope unavailable"
            result.mark_finished(ModuleStatus.SKIPPED)
            return result

        try:
            from playwright.async_api import async_playwright
        except ImportError:
            result.data = {"skipped": "playwright not installed"}
            result.mark_finished(ModuleStatus.SKIPPED)
            return result

        responses: list[dict] = []
        websockets: list[str] = []
        requested: list[str] = []
        bcfg = ctx.config.browser

        try:
            async with async_playwright() as pw:
                browser = await pw.chromium.launch(headless=True)
                try:
                    page = await browser.new_page(
                        user_agent=ctx.config.http.user_agent, ignore_https_errors=True
                    )
                    # Authenticated scan: seed the target's cookies so the SPA
                    # renders its logged-in state. Cookies are domain-scoped by
                    # the browser, so they never reach third-party hosts.
                    cookies = _parse_cookies(ctx.config.http.cookie, ctx.target)
                    if cookies:
                        await page.context.add_cookies(cookies)  # type: ignore[arg-type]

                    # Every request — and every redirect hop — is checked against
                    # scope and the SSRF guard before the browser may make it.
                    from ...engine.browser_gate import make_route_gate
                    from ...engine.ssrf_guard import SsrfGuard

                    guard = SsrfGuard(
                        allow_private_targets=ctx.config.scope.allow_private_targets)
                    await page.route("**/*", make_route_gate(guard, ctx.scope.is_allowed))
                    page.on("request", lambda r: requested.append(r.url))
                    page.on("response", lambda r: responses.append(_resp_dict(r)))
                    page.on("websocket", lambda ws: websockets.append(ws.url))

                    try:
                        await page.goto(
                            ctx.target.base_url,
                            wait_until=bcfg.wait_until,
                            timeout=bcfg.nav_timeout_ms,
                        )
                    except Exception as nav:  # noqa: BLE001 - partial render still useful
                        # A slow SPA/CDN may not reach the wait state in time; the
                        # DOM is often already rendered, so proceed best-effort
                        # instead of failing the whole module.
                        log.warning("navigation wait timed out; using partial render",
                                    error=str(nav))
                    # Let a client-rendered app hydrate and fire its XHRs, without
                    # depending on networkidle (which busy pages never reach).
                    try:
                        await page.wait_for_timeout(bcfg.settle_ms)
                    except Exception:  # noqa: BLE001, S110 - settle is best-effort
                        pass

                    title = await page.title()
                    dom_length = len(await page.content())
                    screenshot_path = await self._screenshot(page, ctx, bcfg)
                finally:
                    await browser.close()
        except Exception as exc:  # noqa: BLE001 - browser problems must not crash the scan
            result.error = f"browser error: {type(exc).__name__}: {exc}"
            result.mark_finished(ModuleStatus.FAILED)
            log.warning("browser mode failed", error=str(exc))
            return result

        endpoints = self._observed_endpoints(ctx, responses, websockets)
        ctx.shared[BROWSER_ENDPOINTS_KEY] = endpoints

        result.data = {
            "title": title,
            "dom_length": dom_length,
            "requests": len(requested),
            "responses": len(responses),
            "websockets": _unique(websockets),
            "observed_endpoints": len(endpoints),
            "screenshot": screenshot_path,
        }
        result.stats = {"requests": len(requested), "observed_endpoints": len(endpoints)}
        result.evidence.append(
            Evidence(
                source=self.name,
                url=ctx.target.base_url,
                description="Browser render summary",
                data={k: result.data[k] for k in ("title", "requests", "observed_endpoints")},
            )
        )
        result.mark_finished(ModuleStatus.SUCCESS)
        log.info("browser render complete", endpoints=len(endpoints), requests=len(requested))
        return result

    def _observed_endpoints(self, ctx, responses: list[dict], websockets: list[str]) -> list[dict]:
        out: dict[str, dict] = {}
        for r in responses:
            if r["resource_type"] in ("xhr", "fetch"):
                kind = "graphql" if "graphql" in r["url"].lower() else "rest"
                out[r["url"]] = {
                    "url": r["url"], "method": r["method"], "status": r["status"], "kind": kind,
                    "observation": str(Observation.OBSERVED),
                }
        for ws in _unique(websockets):
            out[ws] = {
                "url": ws, "method": None, "status": None, "kind": "websocket",
                "observation": str(Observation.OBSERVED),
            }
        return list(out.values())

    async def _screenshot(self, page, ctx, bcfg) -> str | None:
        if not bcfg.screenshots or not bcfg.screenshot_dir:
            return None
        try:
            directory = Path(bcfg.screenshot_dir)
            directory.mkdir(parents=True, exist_ok=True)  # noqa: ASYNC240 - one-off tiny mkdir
            path = directory / f"{ctx.scan_id}.png"
            await page.screenshot(path=str(path), full_page=True)
            return str(path)
        except Exception:  # noqa: BLE001 - a failed screenshot is non-fatal
            return None


def _resp_dict(response) -> dict:
    req = response.request
    return {
        "url": response.url,
        "status": response.status,
        "method": req.method,
        "resource_type": req.resource_type,
        "content_type": response.headers.get("content-type"),
    }


def _parse_cookies(cookie: str | None, target) -> list[dict]:
    """Parse a raw 'k=v; k2=v2' Cookie string into Playwright cookie dicts.

    Scoped to the target host + path '/' so the browser only sends them to the
    target domain (never third parties).
    """
    if not cookie or target is None:
        return []
    out: list[dict] = []
    for part in cookie.split(";"):
        name, sep, value = part.strip().partition("=")
        if sep and name:
            out.append({
                "name": name.strip(), "value": value.strip(),
                "domain": target.hostname, "path": "/",
            })
    return out


def _unique(items) -> list[str]:
    seen: dict[str, None] = {}
    for it in items:
        seen.setdefault(it, None)
    return list(seen)
