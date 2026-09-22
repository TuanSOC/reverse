"""Pure static analysis of a single JS file (no I/O) — easy to unit-test."""

from __future__ import annotations

import hashlib
from dataclasses import dataclass, field

from . import patterns


def _mask(value: str) -> str:
    if len(value) <= 6:
        return "****"
    return f"{value[:4]}…****({len(value)} chars)"


@dataclass
class SecretHit:
    kind: str
    masked: str


@dataclass
class JsAnalysis:
    url: str
    size: int
    sha256: str
    endpoints: list[str] = field(default_factory=list)  # referenced API paths
    urls: list[str] = field(default_factory=list)  # absolute URLs
    websockets: list[str] = field(default_factory=list)
    graphql: bool = False
    analytics_ids: list[str] = field(default_factory=list)
    cloud_refs: list[str] = field(default_factory=list)
    secrets: list[SecretHit] = field(default_factory=list)
    framework_clues: list[str] = field(default_factory=list)
    sourcemap_url: str | None = None
    truncated: bool = False
    # Retained JS source (capped) for downstream static analysis (dom_security).
    content: str = ""


def _dedup(items: list[str], cap: int = 200) -> list[str]:
    seen: dict[str, None] = {}
    for it in items:
        if it not in seen:
            seen[it] = None
        if len(seen) >= cap:
            break
    return list(seen)


def analyze_js(url: str, content: str, *, truncated: bool = False) -> JsAnalysis:
    """Extract endpoints, URLs, secrets, and clues from a JS source string."""
    data = content
    result = JsAnalysis(
        url=url,
        size=len(content.encode("utf-8", errors="ignore")),
        sha256=hashlib.sha256(content.encode("utf-8", errors="ignore")).hexdigest(),
        truncated=truncated,
        content=content[:400_000],  # cap retained source to bound memory
    )

    result.endpoints = _dedup([m.group(1) for m in patterns.API_PATH.finditer(data)])
    result.websockets = _dedup(patterns.WEBSOCKET.findall(data))
    # Absolute URLs excluding websocket ones (already captured).
    result.urls = _dedup(
        [u for u in patterns.ABSOLUTE_URL.findall(data)]
    )
    result.graphql = bool(patterns.GRAPHQL.search(data))
    result.analytics_ids = _dedup([m.group(1) for m in patterns.ANALYTICS.finditer(data)])
    result.cloud_refs = _dedup([m.group(1) for m in patterns.CLOUD.finditer(data)])

    sm = patterns.SOURCEMAP.search(data)
    if sm:
        result.sourcemap_url = sm.group(1).strip()

    seen_secrets: set[tuple[str, str]] = set()
    for kind, pat in patterns.SECRETS:
        for m in pat.finditer(data):
            raw = m.group(0)
            key = (kind, raw)
            if key in seen_secrets:  # same value repeated in the file → one finding
                continue
            seen_secrets.add(key)
            result.secrets.append(SecretHit(kind=kind, masked=_mask(raw)))

    for name, pat in patterns.FRAMEWORK_CLUES:
        if pat.search(data):
            result.framework_clues.append(name)

    return result
