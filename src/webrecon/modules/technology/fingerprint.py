"""Pure fingerprinting engine (no I/O) — matches signals, aggregates evidence.

Distinguishes *observation* correctly: a technology confirmed by a response
header or cookie is stronger than one guessed from an HTML substring. Multiple
independent sources for the same tech bump confidence one level (capped at HIGH
unless a version is also recovered, which yields CONFIRMED).
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field

from ...core.enums import CONFIDENCE_ORDER, Confidence
from .signatures import COOKIE, HEADER, HTML, META, SCRIPT, SIGNATURES, Signature


@dataclass
class TechEvidence:
    source: str
    detail: str
    version: str | None = None


@dataclass
class TechDetection:
    name: str
    category: str
    version: str | None = None
    confidence: Confidence = Confidence.LOW
    evidence: list[TechEvidence] = field(default_factory=list)

    @property
    def sources(self) -> set[str]:
        return {e.source for e in self.evidence}


_URL_VERSION = re.compile(
    r"[?&]v(?:er|ersion)?=(\d+\.\d[\w.]*)"     # ?v=1.2.3 / ?ver=1.2
    r"|@(\d+\.\d[\w.]*)"                        # /pkg@1.2.3/
    r"|[-.](\d+\.\d+(?:\.\d+)?)(?:\.min)?\.js"  # lib-1.2.3.min.js
)


def extract_url_version(url: str) -> str | None:
    """Best-effort version pulled from an asset URL (?v=, @ver/, -1.2.3.min.js)."""
    m = _URL_VERSION.search(url)
    if not m:
        return None
    return next((g for g in m.groups() if g), None)


def _match(sig: Signature, text: str) -> tuple[bool, str | None]:
    m = re.search(sig.pattern, text, re.IGNORECASE)
    if not m:
        return False, None
    version = None
    if sig.version_group is not None:
        try:
            version = m.group(sig.version_group)
        except IndexError:
            version = None
    return True, version


# Category for a framework recovered from JS *content* clues (javascript module).
# Content markers survive minification but not always obfuscation, so these are
# recorded at MEDIUM — stronger than an HTML-substring guess, weaker than a header.
_JS_CLUE_CATEGORY: dict[str, str] = {
    "React": "frontend", "Preact": "frontend", "SolidJS": "frontend",
    "Svelte": "frontend", "Vue.js": "frontend", "Angular": "frontend",
    "Next.js": "frontend", "Vite": "build-tool", "webpack": "build-tool",
    "Sentry": "monitoring",
}


def fingerprint(
    *,
    headers: dict[str, str],
    cookies: list[str],
    html: str,
    script_urls: list[str],
    meta_generator: str | None,
    js_clues: list[str] | None = None,
) -> list[TechDetection]:
    """Run all signatures against the observed signals and aggregate results."""
    headers = {k.lower(): v for k, v in headers.items()}
    detections: dict[str, TechDetection] = {}

    def record(sig: Signature, detail: str, version: str | None) -> None:
        det = detections.get(sig.tech)
        if det is None:
            det = TechDetection(name=sig.tech, category=sig.category, confidence=sig.confidence)
            detections[sig.tech] = det
        det.evidence.append(TechEvidence(sig.source, detail, version))
        if version and not det.version:
            det.version = version
        # Raise confidence to the strongest single signal.
        if CONFIDENCE_ORDER[sig.confidence] > CONFIDENCE_ORDER[det.confidence]:
            det.confidence = sig.confidence

    for sig in SIGNATURES:
        if sig.source == HEADER and sig.header:
            value = headers.get(sig.header)
            if value is not None:
                ok, ver = _match(sig, value)
                if ok:
                    record(sig, f"{sig.header}: {value}", ver)
        elif sig.source == COOKIE:
            for name in _cookie_names(cookies):
                ok, ver = _match(sig, name)
                if ok:
                    record(sig, f"cookie {name}", ver)
        elif sig.source == HTML and html:
            ok, ver = _match(sig, html)
            if ok:
                record(sig, "matched in HTML body", ver)
        elif sig.source == SCRIPT:
            for url in script_urls:
                ok, ver = _match(sig, url)
                if ok:
                    # Fall back to a version embedded in the asset URL itself
                    # (?v=1.2.3, @1.2.3/, -1.2.3.min.js) when the signature's own
                    # pattern did not capture one.
                    record(sig, f"script {url}", ver or extract_url_version(url))
                    break
        elif sig.source == META and meta_generator:
            ok, ver = _match(sig, meta_generator)
            if ok:
                record(sig, f"meta generator: {meta_generator}", ver)

    # Framework clues recovered from JS content by the javascript module.
    for clue in js_clues or []:
        cat = _JS_CLUE_CATEGORY.get(clue)
        if cat is None:
            continue
        det = detections.get(clue)
        if det is None:
            det = TechDetection(name=clue, category=cat, confidence=Confidence.MEDIUM)
            detections[clue] = det
        det.evidence.append(TechEvidence("js_content", f"clue in JS: {clue}"))
        if CONFIDENCE_ORDER[Confidence.MEDIUM] > CONFIDENCE_ORDER[det.confidence]:
            det.confidence = Confidence.MEDIUM

    # Post-process: independent-source corroboration + version bonus.
    for det in detections.values():
        if len(det.sources) >= 2 and CONFIDENCE_ORDER[det.confidence] < CONFIDENCE_ORDER[
            Confidence.HIGH
        ]:
            det.confidence = _bump(det.confidence)
        if det.version and det.confidence == Confidence.HIGH:
            det.confidence = Confidence.CONFIRMED

    return sorted(
        detections.values(),
        key=lambda d: CONFIDENCE_ORDER[d.confidence],
        reverse=True,
    )


def _cookie_names(set_cookie: list[str]) -> list[str]:
    names = []
    for raw in set_cookie:
        first = raw.split(";", 1)[0]
        if "=" in first:
            names.append(first.split("=", 1)[0].strip())
    return names


def _bump(conf: Confidence) -> Confidence:
    order = [Confidence.LOW, Confidence.MEDIUM, Confidence.HIGH, Confidence.CONFIRMED]
    idx = order.index(conf)
    return order[min(idx + 1, len(order) - 1)]
