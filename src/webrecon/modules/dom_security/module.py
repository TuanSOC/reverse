"""Client-side DOM security module (§8-adjacent).

Statically analyzes the public JavaScript retained by the ``javascript`` module
(``ctx.shared["js_analysis"]``) for two client-side risk classes: DOM XSS
source→sink patterns and unguarded prototype-pollution deep-merge loops. Purely
static and heuristic — findings are POTENTIAL and always carry the matched code
snippet as evidence. No code is executed.
"""

from __future__ import annotations

from ...core.enums import (
    Confidence,
    FindingCategory,
    ModuleStatus,
    Observation,
    Severity,
)
from ...core.models import Evidence, Finding, ModuleResult
from ...core.module import ScannerModule
from ...core.registry import default_registry
from .analysis import find_dom_xss, find_prototype_pollution


@default_registry.register
class DomSecurityModule(ScannerModule):
    name = "dom_security"
    version = "0.1.0"
    requires = ("javascript",)
    description = "Static DOM XSS + prototype-pollution heuristics over public JS."

    async def run(self, ctx) -> ModuleResult:  # type: ignore[override]
        result = self.new_result()
        result.mark_started()
        log = ctx.bind_logger(self.name)

        analyses = ctx.shared.get("js_analysis") or []
        files = [a for a in analyses if getattr(a, "content", "")]
        if not files:
            result.data = {"skipped": "no JS content available"}
            result.mark_finished(ModuleStatus.SKIPPED)
            return result

        xss = 0
        proto = 0
        for a in files:
            for hit in find_dom_xss(a.content):
                xss += 1
                result.findings.append(self._f(
                    "dom.xss.source_to_sink",
                    f"Potential DOM XSS at line {hit.line} ({hit.detail})",
                    Severity.MEDIUM, a.url,
                    "A URL/DOM taint source flows into a dangerous sink: "
                    f"{hit.flow} (line {hit.line}).",
                    "If the source is attacker-controlled and unsanitized, this enables DOM XSS.",
                    "Never write untrusted input into innerHTML/document.write/eval. "
                    "Use textContent for text, or sanitize markup with a vetted "
                    "library, e.g. `el.innerHTML = DOMPurify.sanitize(userInput)`; "
                    "and deploy a strict CSP (e.g. `script-src 'self'; "
                    "object-src 'none'; base-uri 'none'`).",
                    hit,
                ))
            for hit in find_prototype_pollution(a.content):
                proto += 1
                result.findings.append(self._f(
                    "dom.prototype_pollution",
                    f"Potential client-side prototype pollution (line {hit.line})",
                    Severity.MEDIUM, a.url,
                    "A recursive/deep-merge loop assigns keys without "
                    f"filtering __proto__ (line {hit.line}).",
                    "Attacker-controlled keys could pollute Object.prototype, "
                    "altering app behavior.",
                    "Reject __proto__/constructor/prototype keys and use a "
                    "null-prototype target or Map, e.g. "
                    "`if (['__proto__','constructor','prototype'].includes(k)) "
                    "continue;` or `Object.create(null)`.",
                    hit,
                ))

        result.data = {"files_analyzed": len(files), "dom_xss": xss, "prototype_pollution": proto}
        result.stats = {"dom_xss": xss, "prototype_pollution": proto}
        result.mark_finished(ModuleStatus.SUCCESS)
        log.info("dom_security complete", dom_xss=xss, proto=proto)
        return result

    def _f(self, cid, name, sev, url, desc, impact, rec, hit) -> Finding:
        return Finding(
            check_id=cid, name=name, category=FindingCategory.VULNERABILITY,
            severity=sev, confidence=Confidence.LOW, observation=Observation.POTENTIAL,
            module=self.name, description=desc, impact=impact, recommendation=rec,
            evidence=[Evidence(source=self.name, url=url, description=hit.detail,
                               data={"snippet": hit.snippet, "kind": hit.kind,
                                     "line": hit.line, "flow": hit.flow})],
        )
