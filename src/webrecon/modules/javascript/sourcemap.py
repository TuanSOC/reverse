"""Source map (.map) parsing (§9).

Reads the JSON metadata only — never the reconstructed source content beyond
counting/listing paths — and never fetches anything out of scope. A publicly
reachable source map is itself the finding.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field


@dataclass
class SourceMapInfo:
    version: int | None = None
    sources_count: int = 0
    source_root: str | None = None
    source_paths: list[str] = field(default_factory=list)
    has_sources_content: bool = False


def parse_source_map(text: str, *, max_paths: int = 100) -> SourceMapInfo | None:
    """Parse a source map JSON document; return None if it is not a source map."""
    try:
        doc = json.loads(text)
    except (json.JSONDecodeError, ValueError):
        return None
    if not isinstance(doc, dict) or "sources" not in doc:
        return None
    sources = doc.get("sources") or []
    if not isinstance(sources, list):
        sources = []
    return SourceMapInfo(
        version=doc.get("version") if isinstance(doc.get("version"), int) else None,
        sources_count=len(sources),
        source_root=doc.get("sourceRoot") or None,
        source_paths=[str(s) for s in sources[:max_paths]],
        has_sources_content=bool(doc.get("sourcesContent")),
    )
