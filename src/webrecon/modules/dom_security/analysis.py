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
# Prototype pollution needs *depth*: a plain shallow copy (dst[k]=src[k]) is not
# exploitable, but a recursive/nested merge is. Require one of these signals so
# that minified prop-copy loops (e.g. React's ref-copy) don't false-positive.
_DEEP_SIGNAL = re.compile(
    r"\b(?:merge|extend|deep\w*|mergeDeep|defaultsDeep)\s*\("  # named deep-merge call
    r"|typeof\s+[\w.$\[\]]+\s*===?\s*[`'\"]object"            # isObject branch
    r"|\[[^\]]+\]\s*\[[^\]]+\]\s*="                           # nested bracket assign x[a][b]=
    r"|isObject|isPlainObject",
)


# A variable assigned directly from a taint source: `var x = location.hash…`.
# Captures the variable name so we can follow it into a sink (1-hop taint).
_TAINT_ASSIGN = re.compile(
    r"(?:var|let|const)\s+([A-Za-z_$][\w$]*)\s*=\s*[^;\n]*?(?:"
    r"location\.(?:search|hash|href|pathname)|document\.(?:URL|documentURI|referrer|cookie)"
    r"|window\.name|URLSearchParams)",
    re.IGNORECASE,
)


@dataclass
class DomHit:
    kind: str            # "dom_xss" | "prototype_pollution"
    detail: str
    snippet: str
    line: int = 0        # 1-based line of the sink in the source
    flow: str = ""       # source → [var] → sink taint path


def _line_of(text: str, offset: int) -> int:
    return text.count("\n", 0, offset) + 1


def _snippet(text: str, start: int, end: int, pad: int = 70) -> str:
    s = max(0, start - pad)
    e = min(len(text), end + pad)
    return text[s:e].strip().replace("\n", " ")[:220]


def find_dom_xss(content: str, cap: int = 10) -> list[DomHit]:
    """Trace URL/DOM taint sources into dangerous sinks, with line + flow.

    Two flow shapes are reported:
    - *direct*: a source appears in the sink's own expression window, and
    - *via-variable*: a variable assigned from a source (1-hop) is used at the
      sink — a lightweight taint trace that catches ``var q = location.hash; …;
      el.innerHTML = q``.
    """
    # Map tainted variable name → (source expression, assignment line).
    tainted: dict[str, tuple[str, int]] = {}
    for a in _TAINT_ASSIGN.finditer(content):
        src_expr = SOURCES.search(a.group(0))
        tainted.setdefault(a.group(1), (
            src_expr.group(0) if src_expr else "url-source", _line_of(content, a.start()),
        ))

    hits: list[DomHit] = []
    seen: set[str] = set()
    for m in SINKS.finditer(content):
        window = content[max(0, m.start() - 160): m.end() + 60]
        sink = m.group(0).strip()
        line = _line_of(content, m.start())

        src = SOURCES.search(window)
        flow: str | None = None
        if src:
            flow = f"{src.group(0)} → {sink}"
            detail = f"{src.group(0)}→{sink}"
        else:
            # via-variable: a tainted var used within the sink window.
            for var, (src_txt, src_line) in tainted.items():
                if re.search(rf"\b{re.escape(var)}\b", window):
                    flow = f"{src_txt} → var {var} (line {src_line}) → {sink}"
                    detail = f"{src_txt}→{var}→{sink}"
                    break
        if flow is None:
            continue
        if detail in seen:
            continue
        seen.add(detail)
        hits.append(DomHit(
            "dom_xss", detail, _snippet(content, m.start(), m.end()),
            line=line, flow=flow,
        ))
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
        if not _DEEP_SIGNAL.search(region):
            continue  # shallow prop-copy, not a recursive merge → not exploitable
        hits.append(DomHit("prototype_pollution", "unguarded deep-merge loop",
                           _snippet(content, m.start(), m.end()),
                           line=_line_of(content, m.start())))
        if len(hits) >= cap:
            break
    return hits
