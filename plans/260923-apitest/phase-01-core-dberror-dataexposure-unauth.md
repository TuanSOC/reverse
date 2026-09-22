---
phase: 1
title: Core + DB-error + Data-exposure + Unauth
status: in-progress
priority: P1
effort: 1.5d
dependencies: []
---

# Phase 1: Core harness + db_error + data_exposure + unauth_access

## Overview
Establish the opt-in `apitest` module + the safe request harness (structurally
GET-only, observed-only, verb-filtered, budget-capped) and the three checks that
need no injection payloads: DB error leakage, sensitive-data exposure, broken
auth. Incorporates red-team fixes #2–#5, #7–#9, #11 and lays the param groundwork
for P2 (#1).

## Requirements
- Functional: with `--active`, probe only `observed`, in-scope, non-verb REST
  endpoints; GET baseline; emit `apitest.db_error`, `apitest.data_exposure`,
  `apitest.auth.unauth_access`. Without `--active` → SKIPPED.
- Non-functional: GET-only enforced at runtime; ≤200-request module counter;
  reuse scope+SSRF+rate-limit; findings feed the security risk classifier.

## Architecture
- **Param capture (red-team #1 groundwork)**: `modules/api/classify.py` —
  `Endpoint` gains `params: set[str]`; `EndpointAggregator.add()` parses the
  incoming URL's query keys and unions them into the endpoint's `params` before
  the query is normalized away. (Enables P2 to build `?param='` probes.)
- **SafeGetEngine (red-team #3)**: `modules/apitest/safe_engine.py` — thin
  wrapper over `HttpEngine` exposing only `get(url)`; a `request()` that receives
  any method ≠ GET raises `ValueError`. All apitest requests go through it.
- **signatures.py (pure)**: DB-error regexes (`SQLSTATE\[`, `ORA-\d{5}`,
  `SQL syntax.*MySQL`, `PostgreSQL.*ERROR`, `SQLite3::`, `Microsoft OLE DB`,
  ORM traces); `looks_substantive_json(body)` (JSON array len ≥ 5 OR object with
  ≥ 5 keys); `SENSITIVE_PATH = admin|internal|account|user`; secret/PII detection
  reusing `javascript.patterns.SECRETS` + key-name regex
  (`password|passwd|secret|token|api[_-]?key|ssn|authorization`); `mask_value()`.
- **module.py**: `ApiTestModule(ScannerModule)`, name `apitest`,
  `requires=("api",)`. Skip if `not config.active` or no endpoints. Build the
  work-list = endpoints with `observation=="observed"` AND `in_scope` AND
  `kind=="rest"` AND path NOT matching the verb deny-list (red-team #2/#4).
  Per endpoint (module-side counter, stop at 200 — red-team #9): GET baseline,
  run db_error + data_exposure + unauth checks.
- **Precedence (red-team #8)**: if a response trips a DB-error signature, emit
  `db_error` and do NOT also emit `data_exposure` from a stack-trace on the same
  body.
- **unauth (red-team #5)**: flag only when body is substantive JSON AND
  (data_exposure tripped OR path is sensitive). Confidence MEDIUM, POTENTIAL.
- Register in `modules/__init__`; add `"apitest"` to security `_UPSTREAM`.

## Related Code Files
- Create: `modules/apitest/{__init__.py,module.py,signatures.py,safe_engine.py}`
- Modify: `core/config.py` (`active`), `modules/api/classify.py` (Endpoint.params
  + aggregator), `modules/__init__.py`, `modules/security/module.py` (_UPSTREAM),
  `modules/disclosure.py` (add `mask_value`), `tests/fixtures/mock_site.py`
  (vuln API routes), `tests/integration/test_pipeline.py` (ALL_MODULES + skip)
- Create tests: `tests/unit/test_apitest_signatures.py`,
  `tests/unit/test_apitest_safety.py`, `tests/integration/test_apitest.py`,
  `tests/unit/test_api_classify.py` (extend for params capture)

## Implementation Steps (TDD — tests first)
1. **Test** signatures: DB-error regexes match samples, not clean JSON;
   `looks_substantive_json` true/false cases; secret/PII detection + `mask_value`
   never leaks raw values.
2. **Test** safety (`test_apitest_safety.py`): SafeGetEngine.get works;
   any non-GET raises; module SKIPPED when `active=False` (zero requests);
   referenced/out-of-scope/verb endpoints are NOT probed; module halts at the
   200 budget; serialized Finding evidence contains no raw secret/PII.
3. **Test** api params: `EndpointAggregator.add("…/x?a=1&b=2", …)` → endpoint
   `params == {"a","b"}`; param-less URL → empty.
4. **Test** integration: `active=True` on mock → `db_error`, `data_exposure`,
   `auth.unauth_access` fire on the right routes; a public non-sensitive JSON
   endpoint does NOT raise unauth (low FP); a DB-error body yields `db_error`
   only (precedence).
5. Add mock routes: `/api/users` (JSON array ≥5 records with `email`+`token`,
   200 no auth, path sensitive → data_exposure + unauth), `/api/config` (public
   benign JSON → no unauth), `/api/db-error` (`SQLSTATE[42000]…` body),
   `/api/delete?id=` (verb — must be skipped).
6. Implement signatures, safe_engine, Endpoint.params, module → green.
7. Wire config + registration + `_UPSTREAM` + `ALL_MODULES`; ruff+mypy+pytest.

## Success Criteria
- [ ] `active=False` → SKIPPED, zero requests.
- [ ] Only `observed` + in-scope + non-verb rest endpoints probed (tested).
- [ ] SafeGetEngine raises on any non-GET method (tested).
- [ ] Budget halts at 200 (tested).
- [ ] `db_error`, `data_exposure`, `auth.unauth_access` fire correctly; public
      benign JSON does not raise unauth; DB-error body → single `db_error`.
- [ ] Raw secret/PII never present in serialized evidence.
- [ ] ruff + mypy clean; full suite green.

## Risk Assessment
- unauth FP → corroboration (data_exposure OR sensitive path) + concrete
  "substantive" definition; MEDIUM/POTENTIAL.
- State-changing GET → verb deny-list + observed-only, applied before any
  request; documented.
- Cross-module change to `api/classify.py` (params) → covered by extended
  `test_api_classify.py`; keep it additive (new field, default empty set).
