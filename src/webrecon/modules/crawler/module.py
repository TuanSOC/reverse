"""Bounded, scope-enforced crawler (§7).

BFS from the target base URL. Every candidate URL passes the scope engine (and,
by default, robots.txt) before it is fetched, and the crawl is hard-bounded by
max depth / pages / requests so it can never run away (§7). Only HTML pages are
fetched for link extraction; other resources are recorded as *referenced*
assets without downloading their bodies.

The crawler reuses the base-page response already fetched by the ``http`` module
so it never double-fetches the root.
"""

from __future__ import annotations

import hashlib

from ...core.enums import ModuleStatus
from ...core.models import Evidence, ModuleResult
from ...core.module import ScannerModule
from ...core.registry import default_registry
from ...core.urls import normalize_url, parse_url
from ..http.module import PRIMARY_RESPONSE_KEY
from .models import CrawledPage, CrawlInventory, DiscoveredAsset
from .parser import parse_html
from .robots import RobotsRules, parse_robots
from .sitemap import parse_sitemap

_HTML_TYPES = ("text/html", "application/xhtml")


@default_registry.register
class CrawlerModule(ScannerModule):
    name = "crawler"
    version = "0.1.0"
    requires = ("http",)
    description = "Bounded BFS crawl; link/asset/form/robots/sitemap discovery."

    async def run(self, ctx) -> ModuleResult:  # type: ignore[override]
        result = self.new_result()
        result.mark_started()
        log = ctx.bind_logger(self.name)

        target = ctx.target
        primary = ctx.shared.get(PRIMARY_RESPONSE_KEY)
        if target is None or ctx.http is None or primary is None:
            result.error = "target/http/primary response unavailable"
            result.mark_finished(ModuleStatus.SKIPPED)
            return result

        cfg = ctx.config
        inv = CrawlInventory()
        visited: set[str] = set()
        asset_urls: set[str] = set()
        requests_made = 0

        robots, robots_reqs = await self._load_robots(ctx, target.base_url, inv, log)
        requests_made += robots_reqs

        # Seed the queue from the already-fetched base page.
        queue: list[tuple[str, int, str | None]] = []
        self._ingest_response(
            ctx, inv, visited, asset_urls, queue, primary, depth=0, discovered_from=None
        )

        # BFS.
        while queue:
            if len(inv.pages) >= cfg.scope.max_pages:
                inv.stats["stopped_reason"] = "max_pages"
                break
            if requests_made >= cfg.scope.max_requests:
                inv.stats["stopped_reason"] = "max_requests"
                break
            try:
                ctx.cancellation.raise_if_cancelled()
            except Exception:  # noqa: BLE001 - cancellation surfaces as CANCELLED
                inv.stats["stopped_reason"] = "cancelled"
                result.mark_finished(ModuleStatus.CANCELLED)
                ctx.shared["inventory"] = inv
                return result

            url, depth, src = queue.pop(0)
            norm = normalize_url(url, keep_query=cfg.crawl.distinct_query)
            if norm in visited:
                continue
            if depth > cfg.scope.max_depth:
                continue
            if not ctx.scope.is_allowed(url):
                continue
            if cfg.crawl.respect_robots and self._robots_blocks(robots, url):
                inv.stats["robots_skipped"] = inv.stats.get("robots_skipped", 0) + 1
                continue

            visited.add(norm)
            try:
                resp = await ctx.http.get(url)
                requests_made += 1
            except Exception as exc:  # noqa: BLE001 - never crash the crawl on one bad URL
                inv.pages.append(
                    CrawledPage(url=url, status_code=None, depth=depth, discovered_from=src)
                )
                log.debug("page fetch failed", url=url, error=str(exc))
                continue

            self._ingest_response(ctx, inv, visited, asset_urls, queue, resp, depth, src)

        requests_made += await self._load_sitemap(ctx, target.base_url, robots, inv, log)

        # Publish + persist.
        ctx.shared["inventory"] = inv
        await self._persist(ctx, inv)

        inv.stats.update(
            {
                "pages": len(inv.pages),
                "assets": len(inv.assets),
                "forms": len(inv.forms),
                "requests": requests_made,
                "sitemap_urls": len(inv.sitemap_urls),
            }
        )
        result.data = {
            "pages": len(inv.pages),
            "assets": len(inv.assets),
            "forms": len(inv.forms),
            "edges": len(inv.edges),
            "sitemap_urls": len(inv.sitemap_urls),
            "stopped_reason": inv.stats.get("stopped_reason", "queue_exhausted"),
        }
        result.stats = inv.stats
        self._sitemap_findings(ctx, result, inv, visited)
        result.evidence.append(
            Evidence(
                source=self.name,
                url=target.base_url,
                description="Crawl inventory summary",
                data=result.data,
            )
        )
        result.mark_finished(ModuleStatus.SUCCESS)
        log.info("crawl complete", **result.data)
        return result

    # -- helpers -----------------------------------------------------------

    def _ingest_response(
        self, ctx, inv, visited, asset_urls, queue, resp, depth, discovered_from
    ) -> None:
        """Record a fetched response as a page + extract links/assets/forms."""
        content_hash = hashlib.sha256(resp.body).hexdigest()
        ctype = (resp.content_type or "").lower()
        is_html = any(t in ctype for t in _HTML_TYPES)
        norm = normalize_url(resp.url, keep_query=ctx.config.crawl.distinct_query)
        visited.add(norm)

        page = CrawledPage(
            url=resp.url,
            status_code=resp.status_code,
            depth=depth,
            content_hash=content_hash,
            content_type=resp.content_type,
            discovered_from=discovered_from,
        )

        if is_html and not resp.truncated:
            extract = parse_html(resp.url, resp.text)
            page.title = extract.title
            page.canonical = extract.canonical
            page.links = extract.links
            page.meta = extract.meta
            for link in extract.links:
                inv.edges.append((resp.url, "links", link))
                queue.append((link, depth + 1, resp.url))
            if ctx.config.crawl.record_assets:
                for asset in extract.assets:
                    self._add_asset(inv, asset_urls, asset, ctx)
                    inv.edges.append((resp.url, "asset", asset.url))
            for form in extract.forms:
                inv.forms.append(form)
                inv.edges.append((resp.url, "form", form.action or resp.url))
        inv.pages.append(page)

    def _add_asset(self, inv, asset_urls, asset: DiscoveredAsset, ctx) -> None:
        if asset.url in asset_urls:
            return
        if len(inv.assets) >= ctx.config.crawl.max_assets:
            return
        asset_urls.add(asset.url)
        inv.assets.append(asset)

    def _robots_blocks(self, robots: RobotsRules | None, url: str) -> bool:
        if robots is None:
            return False
        try:
            path = parse_url(url).path
        except ValueError:
            return False
        return robots.is_disallowed(path)

    async def _load_robots(self, ctx, base_url, inv, log) -> tuple[RobotsRules | None, int]:
        """Fetch + parse robots.txt. Returns (rules, requests_made)."""
        robots_url = base_url.rstrip("/") + "/robots.txt"
        try:
            resp = await ctx.http.get(robots_url)
        except Exception as exc:  # noqa: BLE001
            log.debug("robots fetch failed", error=str(exc))
            return None, 0
        if resp.status_code != 200:
            return None, 1
        ua = ctx.config.http.user_agent
        rules = parse_robots(resp.text, user_agent=ua)
        inv.robots_sitemaps = list(rules.sitemaps)
        return rules, 1

    async def _load_sitemap(self, ctx, base_url, robots, inv, log) -> int:
        """Fetch + parse sitemaps. Returns the number of requests made."""
        if not ctx.config.crawl.parse_sitemap:
            return 0
        candidates = list(inv.robots_sitemaps) or [base_url.rstrip("/") + "/sitemap.xml"]
        seen_urls: set[str] = set()
        requests = 0
        for sm_url in candidates[:5]:  # bound recursion breadth
            if not ctx.scope.is_allowed(sm_url):
                continue
            try:
                resp = await ctx.http.get(sm_url)
                requests += 1
            except Exception as exc:  # noqa: BLE001
                log.debug("sitemap fetch failed", url=sm_url, error=str(exc))
                continue
            if resp.status_code != 200:
                continue
            parsed = parse_sitemap(resp.text)
            for u in parsed.urls:
                if u not in seen_urls:
                    seen_urls.add(u)
                    inv.sitemap_urls.append(u)
        # Cap to avoid unbounded growth from a huge sitemap.
        inv.sitemap_urls = inv.sitemap_urls[:10000]
        return requests

    def _sitemap_findings(self, ctx, result, inv, visited) -> None:
        """Informational: URLs in the sitemap the crawl did not reach (§17)."""
        if not inv.sitemap_urls:
            return
        crawled = {p.url for p in inv.pages}
        undiscovered = [u for u in inv.sitemap_urls if u not in crawled][:50]
        if undiscovered:
            result.data["undiscovered_sitemap_urls"] = len(undiscovered)

    async def _persist(self, ctx, inv: CrawlInventory) -> None:
        storage = ctx.storage
        if storage is None:
            return
        await storage.save_crawl(ctx.scan_id, inv)
