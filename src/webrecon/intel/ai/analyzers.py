"""AI analyzers over an :class:`AnalysisContext` (G8).

Contract: every claim cites at least one evidence ID that exists in the context.
Claims citing nothing valid are dropped (and counted in ``rejected_claims``), so a
model can never introduce evidence of its own.

* :class:`StubAnalyzer` — deterministic and offline; used for tests and when no
  key is configured.
* :class:`GroqAnalyzer` — Groq's OpenAI-compatible chat API over plain ``httpx``.
  This is the one network call outside the scope-gated scan engine (it never
  touches the target). The key comes from ``GROQ_API_KEY`` only and is never
  logged, echoed in errors, or persisted.
"""

from __future__ import annotations

import json
import os
import re
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Protocol

from .context import INTERESTING_PARAMS, AnalysisContext

SECTIONS = ("components", "attack_surface", "auth_apis", "static_vs_observed", "gaps")
MAX_CLAIMS_PER_SECTION = 8
MAX_CLAIM_CHARS = 600

GROQ_URL = "https://api.groq.com/openai/v1/chat/completions"
# Override with WEBRECON_AI_MODEL; Groq retires models, so keep this configurable.
DEFAULT_GROQ_MODEL = "openai/gpt-oss-120b"
_KEY_PATTERN = re.compile(r"gsk_[A-Za-z0-9]{8,}")


class AiError(Exception):
    """AI provider failure (message is safe to show: never contains the key)."""


@dataclass
class Claim:
    text: str
    evidence: list[str]

    def to_dict(self) -> dict[str, Any]:
        return {"text": self.text, "evidence": self.evidence}


@dataclass
class AiAnalysis:
    provider: str
    model: str
    app_summary: Claim | None
    sections: dict[str, list[Claim]] = field(default_factory=dict)
    rejected_claims: int = 0
    created_at: str = field(default_factory=lambda: datetime.now(UTC).isoformat())

    def cited_ids(self) -> set[str]:
        ids = set(self.app_summary.evidence) if self.app_summary else set()
        for claims in self.sections.values():
            for c in claims:
                ids.update(c.evidence)
        return ids

    def to_dict(self, ctx: AnalysisContext | None = None) -> dict[str, Any]:
        out: dict[str, Any] = {
            "provider": self.provider, "model": self.model, "created_at": self.created_at,
            "app_summary": self.app_summary.to_dict() if self.app_summary else None,
            "sections": {k: [c.to_dict() for c in self.sections.get(k, [])] for k in SECTIONS},
            "rejected_claims": self.rejected_claims,
        }
        if ctx is not None:  # snapshot the cited evidence so IDs stay resolvable
            out["evidence"] = {i: item.to_dict() for i in sorted(self.cited_ids())
                               if (item := ctx.get(i)) is not None}
        return out


class AiAnalyzer(Protocol):
    provider: str
    model: str

    async def analyze(self, ctx: AnalysisContext) -> AiAnalysis: ...


# -- citation enforcement ------------------------------------------------------


def _claim(raw: Any, valid: set[str]) -> tuple[Claim | None, bool]:
    """Validate one raw claim → (claim or None, was_rejected)."""
    if not isinstance(raw, dict):
        return None, True
    text = raw.get("text")
    if not isinstance(text, str) or not text.strip():
        return None, True
    cited = raw.get("evidence") or []
    if isinstance(cited, str):
        cited = [cited]
    elif not isinstance(cited, list | tuple):
        cited = []  # e.g. a number/bool from a confused model → claim gets rejected
    ids = list(dict.fromkeys(str(c).strip() for c in cited if str(c).strip() in valid))
    if not ids:
        return None, True
    return Claim(text.strip()[:MAX_CLAIM_CHARS], ids), False


def parse_analysis(data: Any, ctx: AnalysisContext, *, provider: str, model: str) -> AiAnalysis:
    """Turn model JSON into an :class:`AiAnalysis`, keeping only grounded claims."""
    if not isinstance(data, dict):
        raise AiError("model returned non-object JSON")
    valid = ctx.ids
    rejected = 0
    summary, bad = _claim(data.get("app_summary"), valid)
    rejected += int(bad and data.get("app_summary") is not None)
    sections: dict[str, list[Claim]] = {}
    for key in SECTIONS:
        raw = data.get(key) or []
        if not isinstance(raw, list):
            raw = [raw]
        kept: list[Claim] = []
        for item in raw:
            c, bad = _claim(item, valid)
            if c is not None and len(kept) < MAX_CLAIMS_PER_SECTION:
                kept.append(c)
            rejected += int(bad)
        sections[key] = kept
    return AiAnalysis(provider, model, summary, sections, rejected)


# -- offline stub ----------------------------------------------------------------


class StubAnalyzer:
    """Deterministic, offline analysis built directly from the evidence."""

    provider = "stub"
    model = "deterministic-v1"

    async def analyze(self, ctx: AnalysisContext) -> AiAnalysis:
        techs = ctx.of_kind("technology")
        eps = ctx.of_kind("endpoint")
        finds = ctx.of_kind("finding")
        stats = ctx.get("S1")
        st = stats.data if stats else {}
        target = ctx.get("X1")
        risk = (target.data.get("risk_level") if target else None) or "unknown"

        tech_names = ", ".join(t.data.get("name", "") for t in techs[:3]) or "no detected stack"
        summary = Claim(
            f"Web application at {ctx.target} ({tech_names}); {st.get('endpoints', 0)} "
            f"endpoints and {st.get('findings', 0)} findings, overall risk {risk}.",
            ["X1", "S1"] + [t.id for t in techs[:3]])

        components = [Claim(f"Uses {t.summary}.", [t.id]) for t in techs]

        surface: list[Claim] = []
        for f in finds:
            if f.data.get("severity") in ("critical", "high"):
                surface.append(Claim(f"{f.data['severity'].title()} issue: {f.data['name']} "
                                     f"({f.data.get('observation')}).", [f.id]))
        for e in eps:
            hits = sorted(set(e.data.get("param_classes") or []) & INTERESTING_PARAMS)
            if hits:
                surface.append(Claim(f"{e.data.get('method') or 'ANY'} {e.data['url']} takes "
                                     f"{', '.join(hits)} parameter(s).", [e.id]))

        auth = ctx.get("A1")
        auth_claims: list[Claim] = []
        if auth is not None:
            a = auth.data
            urls = {x.get("url") for x in a.get("endpoints") or []}
            linked = [e.id for e in eps if e.data.get("url") in urls]
            auth_claims.append(Claim(
                f"Authentication model is '{a.get('kind')}' with {len(urls)} auth-related "
                f"endpoint(s); login form {'present' if a.get('has_login_form') else 'absent'}.",
                ["A1"] + linked))

        static = [e for e in eps if e.data.get("discovery_status") == "STATIC_ONLY"]
        observed = [e for e in eps if e.data.get("observation") == "observed"]
        svo: list[Claim] = []
        if static:
            svo.append(Claim(f"{len(static)} endpoint(s) were only seen statically (JS/sitemap) "
                             "and never requested.", [e.id for e in static[:6]]))
        if observed:
            svo.append(Claim(f"{len(observed)} endpoint(s) were observed responding.",
                             [e.id for e in observed[:6]]))

        gaps: list[Claim] = []
        if st.get("modules_not_successful"):
            gaps.append(Claim("Some modules did not fully run: "
                              + ", ".join(st["modules_not_successful"]) + ".", ["S1"]))
        if st.get("scripts", 0) > st.get("scripts_analyzed", 0):
            gaps.append(Claim(f"{st['scripts'] - st['scripts_analyzed']} script(s) were "
                              "referenced but not analyzed (out of scope or unreachable).", ["S1"]))
        if auth is not None and not auth.data.get("has_session_cookie"):
            gaps.append(Claim("No session cookie was observed; authenticated areas were likely "
                              "not covered.", ["A1", "S1"]))

        sections = {"components": components, "attack_surface": surface,
                    "auth_apis": auth_claims, "static_vs_observed": svo, "gaps": gaps}
        return AiAnalysis(self.provider, self.model, summary,
                          {k: v[:MAX_CLAIMS_PER_SECTION] for k, v in sections.items()})


# -- Groq ----------------------------------------------------------------------

_SYSTEM_PROMPT = """You are a web application security analyst. You receive \
structured evidence that a scanner already collected about ONE web application. \
Each evidence item has an ID (e.g. F1, E3, T2, S1).

Rules:
1. Use ONLY the provided evidence. Never invent endpoints, technologies, \
vulnerabilities or facts.
2. Every claim MUST cite one or more evidence IDs from the input in its "evidence" \
array. Omit any claim you cannot support with an ID.
3. Keep observed (requested and answered) separate from referenced/potential \
(seen statically only). Never present a potential issue as confirmed.
4. This is a defensive assessment: describe surface and risk; never give exploit \
payloads or attack instructions.
5. Be concise and specific. Output ONE JSON object with exactly these keys:
{"app_summary": claim, "components": [claim], "attack_surface": [claim],
 "auth_apis": [claim], "static_vs_observed": [claim], "gaps": [claim]}
where claim = {"text": string, "evidence": [evidence IDs]}.

Meanings: app_summary = what this application is and does; components = \
technologies/frameworks/services it is built from; attack_surface = the most \
security-relevant entry points and why they matter; auth_apis = authentication \
and session APIs and how the flow works; static_vs_observed = which important \
endpoints were only seen statically versus actually observed; gaps = what the \
scan could not determine or cover (cite S1 and related items). At most 8 claims \
per list."""


def _scrub(text: str) -> str:
    return _KEY_PATTERN.sub("gsk_***", text)


class GroqAnalyzer:
    """Groq chat-completions analyzer (JSON mode)."""

    provider = "groq"

    def __init__(self, api_key: str, model: str = DEFAULT_GROQ_MODEL, *,
                 timeout: float = 60.0, transport: Any = None, url: str = GROQ_URL) -> None:
        if not api_key:
            raise AiError("GROQ_API_KEY is not set")
        self._api_key = api_key
        self.model = model
        self._timeout = timeout
        self._transport = transport
        self._url = url

    def __repr__(self) -> str:  # never expose the key via repr/logging
        return f"GroqAnalyzer(model={self.model!r})"

    async def analyze(self, ctx: AnalysisContext) -> AiAnalysis:
        import httpx

        body = {
            "model": self.model,
            "temperature": 0.1,
            "max_tokens": 4096,
            "response_format": {"type": "json_object"},
            "messages": [
                {"role": "system", "content": _SYSTEM_PROMPT},
                {"role": "user", "content": json.dumps(ctx.to_prompt_payload(),
                                                       separators=(",", ":"))},
            ],
        }
        if self.model.startswith("openai/gpt-oss"):
            body["reasoning_effort"] = "low"  # reasoning tokens count against max_tokens
        try:
            async with httpx.AsyncClient(timeout=self._timeout,
                                         transport=self._transport) as client:
                resp = await client.post(
                    self._url, json=body,
                    headers={"Authorization": f"Bearer {self._api_key}"})
        except httpx.HTTPError as exc:
            raise AiError(f"Groq request failed: {_scrub(type(exc).__name__)}") from None
        if resp.status_code != 200:
            raise AiError(f"Groq API error {resp.status_code}: {_error_message(resp)}")
        try:
            content = resp.json()["choices"][0]["message"]["content"]
            data = json.loads(content)
        except (ValueError, KeyError, IndexError, TypeError):
            raise AiError("Groq returned an unparseable response") from None
        return parse_analysis(data, ctx, provider=self.provider, model=self.model)


def _error_message(resp: Any) -> str:
    """Best-effort detail from an error body of any shape (dict/str/list/HTML)."""
    try:
        body: Any = resp.json()
    except ValueError:
        body = resp.text
    msg: Any = None
    if isinstance(body, dict):
        err = body.get("error")
        msg = err.get("message") if isinstance(err, dict) else err
        msg = msg if msg is not None else body.get("message")
    if msg is None:
        msg = body if isinstance(body, str) else json.dumps(body)
    return _scrub(str(msg))[:300] or "no detail"


# -- selection -------------------------------------------------------------------


def load_env_file(path: str | Path = ".env") -> None:
    """Minimal ``.env`` loader: sets variables that are not already set.

    No dependency needed; existing environment always wins, so a real exported
    variable is never overridden by the file.
    """
    p = Path(path)
    if not p.is_file():
        return
    for line in p.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, _, value = line.partition("=")
        key = key.strip().removeprefix("export ").strip()
        value = value.strip().strip('"').strip("'")
        if key and key not in os.environ:
            os.environ[key] = value


def groq_available() -> bool:
    load_env_file()
    return bool(os.environ.get("GROQ_API_KEY"))


def get_analyzer(provider: str | None = None) -> AiAnalyzer:
    """Pick an analyzer: explicit ``provider``, else Groq when a key exists, else stub."""
    load_env_file()
    choice = (provider or os.environ.get("WEBRECON_AI_PROVIDER") or "").lower()
    if choice in ("", "auto"):
        choice = "groq" if os.environ.get("GROQ_API_KEY") else "stub"
    if choice == "stub":
        return StubAnalyzer()
    if choice == "groq":
        return GroqAnalyzer(os.environ.get("GROQ_API_KEY", ""),
                            os.environ.get("WEBRECON_AI_MODEL") or DEFAULT_GROQ_MODEL)
    raise AiError(f"unknown AI provider {choice!r} (use 'groq' or 'stub')")
