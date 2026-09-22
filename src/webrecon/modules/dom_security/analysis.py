"""Pure static heuristics for client-side DOM security (no I/O).

Static, best-effort pattern matching over public JavaScript source. These are
*potential* indicators, not confirmed vulnerabilities — findings are labelled
POTENTIAL and carry the matched code snippet as evidence. Detection only; nothing
is executed.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

# DOM XSS taint sources (attacker-controllable).
SOURCES = re.compile(
    r"location\.(?:search|hash|href|pathname)"
    r"|document\.(?:URL|documentURI|referrer|cookie)"
    r"|window\.name"
    r"|(?:new )?URLSearchParams\(",
    re.IGNORECASE,
)
# Dangerous sinks that can execute or inject markup.
SINKS = re.compile(
    r"\.innerHTML\s*="
    r"|\.outerHTML\s*="
    r"|\.insertAdjacentHTML\s*\("
    r"|document\.write(?:ln)?\s*\("
    r"|\beval\s*\("
    r"|\.html\s*\("               # jQuery $(...).html(...)
    r"|new Function\s*\("
    r"|(?:setTimeout|setInterval)\s*\(\s*['\"]",  # string-eval timers
    re.IGNORECASE,
)

# Recursive/deep-merge pattern: a for-in loop that bracket-assigns.
_MERGE_LOOP = re.compile(
    r"for\s*\(\s*(?:var|let|const)?\s*\w+\s+in\s+[\w.$]+\s*\)[\s\S]{0,240}?\[[^\]]+\]\s*=",
)
# A guard against pollution keys anywhere in the merge region.
_PROTO_GUARD = re.compile(r"__proto__|prototype|constructor|hasOwnProperty|Object\.freeze")


@dataclass
class DomHit:
    kind: str            # "dom_xss" | "prototype_pollution"
    detail: str
    snippet: str


def _snippet(text: str, start: int, end: int, pad: int = 70) -> str:
    s = max(0, start - pad)
    e = min(len(text), end + pad)
    return text[s:e].strip().replace("\n", " ")[:220]


def find_dom_xss(content: str, cap: int = 10) -> list[DomHit]:
    """Flag sinks that have a taint source within the same ~200-char window."""
    hits: list[DomHit] = []
    seen: set[str] = set()
    for m in SINKS.finditer(content):
        window = content[max(0, m.start() - 160): m.end() + 40]
        src = SOURCES.search(window)
        if not src:
            continue
        sink = m.group(0).strip()
        key = f"{src.group(0)}→{sink}"
        if key in seen:
            continue
        seen.add(key)
        hits.append(DomHit("dom_xss", key, _snippet(content, m.start(), m.end())))
        if len(hits) >= cap:
            break
    return hits


def find_prototype_pollution(content: str, cap: int = 5) -> list[DomHit]:
    """Flag deep-merge loops that lack a __proto__/constructor guard."""
    hits: list[DomHit] = []
    for m in _MERGE_LOOP.finditer(content):
        region = content[m.start(): m.end() + 120]
        if _PROTO_GUARD.search(region):
            continue  # appears to filter dangerous keys → not flagged
        hits.append(DomHit("prototype_pollution", "unguarded deep-merge loop",
                           _snippet(content, m.start(), m.end())))
        if len(hits) >= cap:
            break
    return hits
