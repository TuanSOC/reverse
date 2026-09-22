# Design — `apitest` module (Safe Active API/DB Assessment)

Status: approved (brainstorm 2026-09-23), then HARDENED by red-team review.
Authoritative spec is `plans/260923-apitest/` — see its "Red-team resolutions".
Notable overrides vs this brainstorm draft: **GET-only** (OPTIONS dropped);
**error-based SQLi only** (boolean_diff dropped); **probe only `observed`
endpoints** (not referenced/potential); **verb deny-list** for state-changing
GETs; **SafeGetEngine** wrapper enforces GET; **module-side 200-request counter**;
**query params captured** onto `Endpoint.params` (the inventory strips query
strings). Handoff → `/ck:plan` (done) → red-team (done).

## Problem
WebRecon is passive-only. User wants **active API testing** with emphasis on
**DB checks** and **leak/impact detection** on website/app. Must stay inside the
safety boundary (§42): detection-level, non-destructive, no exploitation.

## Requirements (exact)
1. **Output**: new opt-in scanner module `apitest` that, with `--active`, tests
   in-scope discovered API endpoints using **safe benign GET probes** and emits
   findings for: DB error leakage, SQLi susceptibility (detection-only),
   sensitive-data/PII exposure in API responses, broken auth (unauth data
   access), GraphQL introspection/verbose errors. CLI `--active` + dashboard
   checkbox. Findings appear in dashboard/report like every other module.
2. **Acceptance**: with `--active` on the mock vulnerable API → the 5 findings
   fire; WITHOUT `--active` → module `SKIPPED`. All requests GET/OPTIONS,
   idempotent, scope-gated, rate-limited; NO PUT/DELETE/mutation; NO data
   extraction. Tests green; ruff+mypy clean; safety docs updated.
3. **Out of scope**: data dump/exploit (UNION), destructive methods,
   brute-force/credential attacks, credentialed IDOR (deferred — user chose
   unauth-only), DoS/load, DB-port/network scanning, time-based SQLi.
4. **Constraints**: reuse existing `HttpEngine` (scope+SSRF+rate+size caps);
   default OFF; authorized-only; keep passive default intact; ScannerModule
   pattern; no heavy new deps; findings ≤ detection/evidence level.
5. **Touchpoints**: new `modules/apitest/{module,signatures,probes}.py`;
   consumes `ctx.shared["api_endpoints"]`; reuse `modules/disclosure.py`;
   `ScanConfig.active` + CLI `--active` + `StartScanRequest.active`; register in
   `modules/__init__` + security `_UPSTREAM`; docs SECURITY/THREAT_MODEL/MODULES.

## Safety contract (enforced in code)
- Runs only when `config.active` True; else SKIPPED.
- GET/OPTIONS only; probes are idempotent query-string variants.
- No data extraction: SQLi = report susceptibility + error signature evidence;
  never UNION/extraction; never parse/store returned rows.
- Budget: ≤6 probes/endpoint, ≤200 requests total; reuse rate limiter.
- In-scope endpoints only; authorized-only banner.

## Checks (detection-level)
1. **db_error** (medium) — DB error signatures in responses (SQLSTATE, ORA-#####,
   MySQL/Postgres/SQLite syntax, ORM traces).
2. **sqli.susceptible** (high / confidence medium / observation potential) —
   send `'` then `''` on one query param; flag if `'` triggers a DB error that
   `''` does not, or a strong stable differential. No time-based, no UNION.
3. **data_exposure** — JSON responses scanned via `disclosure.py` + secret/token
   patterns + large record arrays with password/token/ssn-like fields; masked.
4. **auth.unauth_access** (medium / potential) — GET without credentials returns
   200 + substantive JSON (not login/empty) → possible missing auth; "verify".
5. **graphql.introspection** (medium) — GET introspection query returns schema;
   also verbose GraphQL errors.

## Internal phases
- P1: config/flag + module skeleton + db_error + data_exposure + unauth_access.
- P2: sqli.susceptible (benign quote differential) — strongest guardrails+tests.
- P3: graphql introspection (GET) + verbose errors.
- P4: dashboard checkbox + docs + authorized-only banner.

## Risks & mitigations
- FP on SQLi/unauth (dynamic pages differ; public APIs are legitimately open) →
  confidence MEDIUM + observation POTENTIAL + "verify manually"; require an
  actual DB-error signature or strong stable differential; never over-claim.
- Probes touch the app → opt-in + rate-limit + read-only + authorized-only.
- GraphQL may be POST-only → skip gracefully.

## Acceptance / validation
- Mock site gains a fake-vulnerable API (`/api/search?q=`, `/api/users`,
  `/graphql`) for tests. Unit tests: signatures + differential logic (pure).
  Integration: module with `--active` produces expected findings; without it,
  SKIPPED. Post-build: run `--active` on gnddt.com (user-owned) to validate.
