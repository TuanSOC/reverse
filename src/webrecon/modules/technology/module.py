"""Technology fingerprinting module (§10).

Collects the observable signals gathered by earlier modules — the primary
response headers/cookies/body plus the crawler's script URLs and meta generator
— and runs them through the pure fingerprint engine. Every detection carries its
confidence and the concrete evidence it was based on; nothing is asserted from a
single weak guess without saying so.
"""

from __future__ import annotations

from ...core.enums import Confidence, ModuleStatus
from ...core.models import Evidence, ModuleResult
from ...core.module import ScannerModule
from ...core.registry import default_registry
from ..http.module import PRIMARY_RESPONSE_KEY
from .fingerprint import TechDetection, fingerprint


@default_registry.register
class TechnologyModule(ScannerModule):
    name = "technology"
    version = "0.1.0"
    requires = ("http", "crawler", "javascript")
    description = "Fingerprint frontend/backend/infra technologies with confidence + evidence."

    async def run(self, ctx) -> ModuleResult:  # type: ignore[override]
        result = self.new_result()
        result.mark_started()
        log = ctx.bind_logger(self.name)

        resp = ctx.shared.get(PRIMARY_RESPONSE_KEY)
        if resp is None:
            result.error = "no primary response"
            result.mark_finished(ModuleStatus.SKIPPED)
            return result

        inv = ctx.shared.get("inventory")
        script_urls: list[str] = []
        meta_generator: str | None = None
        if inv is not None:
            script_urls = [a.url for a in inv.assets if str(a.asset_type) == "script"]
            for page in inv.pages:
                gen = page.meta.get("generator") if page.meta else None
                if gen:
                    meta_generator = gen
                    break

        # Framework clues recovered from JS *content* by the javascript module.
        js_clues: list[str] = []
        for a in ctx.shared.get("js_analysis") or []:
            js_clues.extend(getattr(a, "framework_clues", []) or [])

        detections = fingerprint(
            headers=resp.headers,
            cookies=resp.set_cookie,
            html=resp.text if not resp.truncated else "",
            script_urls=script_urls,
            meta_generator=meta_generator,
            js_clues=sorted(set(js_clues)),
        )

        await self._persist(ctx, detections)

        result.data = {
            "technologies": [
                {
                    "name": d.name,
                    "category": d.category,
                    "version": d.version,
                    "confidence": str(d.confidence),
                    "evidence": [
                        {"source": e.source, "detail": e.detail, "version": e.version}
                        for e in d.evidence
                    ],
                }
                for d in detections
            ]
        }
        for d in detections:
            ctx.event("discovered", f"Technology: {d.name} {d.version or ''}".strip(), {
                "entity": "technology", "name": d.name, "version": d.version,
                "category": d.category, "confidence": str(d.confidence),
            })
        # One module-level evidence item per detection (for the evidence view).
        for d in detections:
            result.evidence.append(
                Evidence(
                    source=self.name,
                    url=resp.url,
                    description=f"Detected {d.name} ({d.category}, {d.confidence})",
                    data={
                        "technology": d.name,
                        "version": d.version,
                        "confidence": str(d.confidence),
                        "signals": [e.detail for e in d.evidence],
                    },
                )
            )
        result.stats = {
            "count": len(detections),
            "high_confidence": sum(
                1 for d in detections if d.confidence in (Confidence.HIGH, Confidence.CONFIRMED)
            ),
        }
        result.mark_finished(ModuleStatus.SUCCESS)
        log.info("technologies detected", count=len(detections))
        return result

    async def _persist(self, ctx, detections: list[TechDetection]) -> None:
        storage = ctx.storage
        if storage is None:
            return
        await storage.save_technologies(ctx.scan_id, detections)
