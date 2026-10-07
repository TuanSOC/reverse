# WebRecon v0.4.0 — Web Application Intelligence Evolution

**Premise:** ~80% of the requested "intelligence engine" already exists (21 modules,
evidence-first findings, observed/referenced/potential endpoints, browser
observation, risk correlation, graph view, reports, auto-login). This evolution
adds the genuine net-new intelligence layers **without rewriting working code**.

## Decisions (locked)
- **JS AST**: Node v22 + vendored `acorn` via subprocess helper; graceful regex fallback.
- **Asset Graph**: builder/view over existing SQLite tables (typed nodes/edges +
  provenance/confidence/evidence refs). No schema rewrite; backward compatible.
- **AI layer**: define the contract + a deterministic offline stub now; real
  Claude call wired behind `--ai` + `ANTHROPIC_API_KEY` later.
- **Scope**: all G1–G8, delivered in 4 phases; each phase ends ruff+mypy+pytest green.

## Phases

### Phase 1 — Intelligence core (G1 params, G2 AST, G3 sourcemap)
- **G2 Parameter intelligence** (`modules/api/params.py`, pure): classify param
  name/shape → object_identifier / user_identifier / redirect / token /
  pagination / sorting / filtering / search / file / callback / unknown +
  confidence + source. Attach to endpoints (new `param_meta`, keep `params`).
- **G1 JS AST** (`modules/javascript/jsast/` Node helper + `ast_js.py`): extract
  fetch/XHR/axios/WebSocket/GraphQL calls → method + normalized path
  (`/api/users/{id}`) + line/col + confidence. Enrich `JsAnalysis`; feed `api`.
- **G3 Source-map deep parse** (`modules/javascript/sourcemap.py` +
  module step): fetch in-scope `.map` via `ctx.http` (SSRF/scope/size safe) →
  reconstruct `sourcesContent` → scan reconstructed code for endpoints + secrets
  (masked) + routes. Finding `exposure.sourcemap.reconstructed`.

### Phase 2 — Correlation & graph (G4, G5)
- **G4 Asset Graph** (`intel/asset_graph.py`): typed GraphNode/GraphEdge with
  source/method/confidence/evidence_ids, assembled from storage. `queries.get_graph`
  upgraded (keeps dashboard shape + extra fields).
- **G5 static/dynamic + auth-flow**: endpoint `discovery_status`
  (STATIC_ONLY / DYNAMIC_ONLY / STATIC_AND_DYNAMIC); `intel/auth_flow.py` builds a
  detection-only login/OAuth flow model from forms_auth + auth endpoints + Set-Cookie.

### Phase 3 — Timeline & dashboard (G6, G7)
- **G6 Event timeline**: `ctx.event(kind,label,data)` → `ScanEvent` table → API.
- **G7 Dashboard**: Attack-surface tree, Endpoint Explorer (filters), JS Explorer,
  Auth-flow view, Event timeline.

### Phase 4 — AI interface (G8, stub)
- `intel/ai/`: `AnalysisContext` (normalized evidence + IDs), `AiAnalyzer` protocol,
  deterministic `StubAnalyzer` (offline, cites evidence IDs), `ClaudeAnalyzer`
  skeleton guarded by key+flag.

## Cross-cutting
- CLI read commands: `endpoints / assets / findings / graph`. Reports gain
  Attack-surface / APIs / Params / Auth sections. No coverage reduction.

## Rejected (KISS / local-first)
- Heavy graph DB (Neo4j): unjustified; builder over SQLite suffices.
- Rebuilding the working 80% (DNS/TLS/tech/cookies/headers/CORS/risk/evidence).
- Any auto-exploitation (already out of scope and preserved).
