# WebRecon v0.4.0 — Session Handoff (continue coding here)

**Working dir:** `D:\Downloads\learn\Saas`  ·  **Python:** `./.venv/Scripts/python.exe` (3.14)
**Node:** v22 available (used for JS AST).  **Repo:** github.com/TuanSOC/reverse (branch `master`).

## The plan (full design)
Read `docs/evolution-v0.4.0.md`. A 4-phase evolution adding real intelligence
layers on top of the existing 21-module scanner **without rewriting the working
~80%**. Locked decisions:
- JS AST = Node + **vendored acorn** (no runtime npm).
- Asset Graph = **builder/view over SQLite** (no schema rewrite, backward compatible).
- AI layer = **Groq API** (user supplied a key — see "AI layer" below).
- Scope = all G1–G8, phased; each phase ends **ruff + mypy + pytest all green**.

## Quality gate (run after every phase — do not skip)
```
./.venv/Scripts/python.exe -m ruff check .
./.venv/Scripts/python.exe -m mypy src
./.venv/Scripts/python.exe -m pytest -q
```
Last known-green full run: **348 passed** (end of Phase 3).

## Status

### ✅ Phase 1 — COMMITTED (`3254b49`)
G1 JS AST (`modules/javascript/jsast/` extract.js + vendored acorn.js/walk.js,
`modules/javascript/ast_js.py`), G2 parameter intelligence (`modules/api/params.py`,
endpoint `param_meta` + `discovery_status`), G3 source-map reconstruction
(`sourcemap.reconstruct_sources` + `javascript/module._analyze_reconstructed`,
finding `exposure.sourcemap.reconstructed`, secrets masked).

### ✅ Phase 2 — COMMITTED (`1e90613`)
G4 asset graph (`intel/asset_graph.py`, `build_asset_graph(db, scan_id)`; `get_graph`
rewired, dashboard shape preserved), G5 auth-flow model (`intel/auth_flow.py`;
`GET /api/scans/{id}/auth-flow`). 338 pytest green.

### ✅ Phase 3 — COMMITTED (timeline + dashboard explorers)
G6 timeline: `ScanContext.event(kind, label, data)` (`core/context.py`, `ScanEvent`,
cap `MAX_SCAN_EVENTS`=5000 → `events_dropped`), events attributed via
`ctx.current_module`; `ScanEventRecord` table `scan_events`; pipeline emits
scan/module/auth/finding events and flushes incrementally (`repo.save_events`);
modules emit discovered/observed (target, crawler page+form, javascript
script+sourcemap+source, api endpoint, technology). Kinds:
`scan|module|auth|discovered|observed|finding`, `data.entity` names the thing.
**API path is `GET /api/scans/{id}/timeline?kind=`** — `/events` stays the
live-progress WebSocket.
JS persistence: `repo.save_js_analyses` enriches script `assets` rows
(content_hash/size_bytes + `meta["js"]`), served by `GET /api/scans/{id}/js`.
Attack-surface tree: `intel/attack_surface.py` (pure, severity rollup) →
`GET /api/scans/{id}/attack-surface`. Fixed asset-graph asset `type` (was None).
G7 dashboard: Endpoint Explorer, JS Explorer, Attack Surface, Auth Flow,
Event Timeline views; old "Timeline / Compare" is now "Compare".

**FIRST ACTION in new session:** read this file, then start **Phase 4** (below).

### ⬜ Phase 4 — AI layer via GROQ (user chose Groq, not stub-only)
- New `src/webrecon/intel/ai/`:
  - `AnalysisContext` — normalized structured evidence (graph + findings +
    endpoints + tech + auth-flow) with stable **evidence IDs**. The model gets
    THIS, never the raw target.
  - `AiAnalyzer` protocol; `StubAnalyzer` (deterministic offline, still cites IDs);
    `GroqAnalyzer` (real). Groq is **OpenAI-compatible**:
    `POST https://api.groq.com/openai/v1/chat/completions`, header
    `Authorization: Bearer $GROQ_API_KEY`, model e.g. `llama-3.3-70b-versatile`.
    Use httpx directly (NOT the scoped scan engine). Opt-in via `--ai` flag.
  - Prompt rule: answer "what is this app / components / attack surface /
    auth-related APIs / static-only vs observed / gaps"; **every claim must cite an
    evidence ID; never invent evidence.**
  - CLI `--ai`; API field; dashboard "AI Analysis" panel.
- 🔐 **SECURITY — critical:**
  - `GROQ_API_KEY` comes from the **environment only**. Never hardcode it, never
    write it into any committed file, never log/print it. Add a `.env` read via
    env var; ensure `.env` is gitignored.
  - The user pasted the key in chat (session before this one) — **advise them to
    rotate it** in the Groq console; do not paste the key value into any file/commit.

## Cross-cutting (any phase)
- CLI read commands: `webrecon endpoints|assets|findings|graph` (read from DB; keep
  existing `scan/scans/report/serve/modules/init-db`).
- Reports (`reporting/html_report.py`, `json_report.py`, `db_report.py`): add
  Attack-surface / APIs / Parameters / Auth-flow sections.

## Hard constraints (unchanged, must hold)
1. Detection/verification only — **no auto-exploitation, no DoS, no brute force**.
2. All scan network I/O via `ctx.http` (HttpEngine) or guarded resolver; AI calls
   are the one exception (external, direct httpx, not scope-gated).
3. Every `Finding` keeps ≥1 `Evidence` (schema-enforced). Secrets always masked.
4. ruff + mypy + pytest 100% green after each phase; never reduce coverage.
5. Reuse existing abstractions; preserve backward compatibility; commit per phase.

## Useful facts
- 21 scanner modules; security `_UPSTREAM` tuple lists modules feeding the risk
  engine — add new finding-producing modules there.
- Dashboard served with `Cache-Control: no-cache` (app.py `/` route).
- Mock site: `tests/fixtures/mock_site.py` (has `/login`,`/account`,`/redir`,`/echo`,
  `/api/item`, app.js + app.js.map w/ sourcesContent for G3).
- Multi-agent coding is OK'd by the user; serialize edits to shared files
  (index.html, app.py, queries.py) to avoid conflicts.
