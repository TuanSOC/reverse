"""Bridge to the vendored acorn-based JS endpoint extractor (Node subprocess).

Runs ``jsast/extract.js`` under Node to parse JavaScript into an AST and pull out
HTTP-ish calls (fetch/XHR/axios/WebSocket/GraphQL) with method + normalized path
(``/api/users/{id}``) + source line/col + confidence. If Node is unavailable or
the parse fails, returns ``[]`` so the caller falls back to regex extraction —
the AST layer is an enrichment, never a hard dependency.
"""

from __future__ import annotations

import asyncio
import json
import shutil
from dataclasses import dataclass
from pathlib import Path

_EXTRACT_JS = Path(__file__).parent / "jsast" / "extract.js"
_NODE = shutil.which("node")
_TIMEOUT = 15.0
_MAX_BYTES = 4_000_000  # cap source fed to Node (bounds memory/time)


@dataclass
class JsCall:
    kind: str          # fetch | xhr | axios | websocket | graphql
    method: str | None
    url: str           # normalized template, e.g. /api/users/{id}
    line: int
    col: int
    confidence: float


def node_available() -> bool:
    return _NODE is not None and _EXTRACT_JS.exists()


async def extract_calls(js_source: str) -> list[JsCall]:
    """Extract endpoint calls from JS via the AST helper (``[]`` on any failure)."""
    node = _NODE
    if node is None or not _EXTRACT_JS.exists() or not js_source:
        return []
    data = js_source[:_MAX_BYTES].encode("utf-8", errors="ignore")
    try:
        proc = await asyncio.create_subprocess_exec(
            node, str(_EXTRACT_JS),
            stdin=asyncio.subprocess.PIPE,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.DEVNULL,
        )
        out, _ = await asyncio.wait_for(proc.communicate(input=data), timeout=_TIMEOUT)
    except (TimeoutError, OSError, ValueError):
        return []
    return _parse_output(out)


def _parse_output(out: bytes) -> list[JsCall]:
    try:
        doc = json.loads(out.decode("utf-8", errors="replace") or "{}")
    except (json.JSONDecodeError, ValueError):
        return []
    if not isinstance(doc, dict) or not doc.get("ok"):
        return []
    calls: list[JsCall] = []
    for c in doc.get("calls", []):
        try:
            calls.append(JsCall(
                kind=str(c["kind"]), method=(c.get("method") or None),
                url=str(c["url"]), line=int(c.get("line") or 0),
                col=int(c.get("col") or 0), confidence=float(c.get("confidence") or 0.6),
            ))
        except (KeyError, TypeError, ValueError):
            continue
    return calls
