---
phase: 2
title: 'SQLi Susceptibility (error-based, detection-only)'
status: in-progress
priority: P1
effort: 0.5d
dependencies:
  - 1
---

# Phase 2: SQLi susceptibility — error-based only (detection-only)

## Overview
For observed, non-verb endpoints that carry captured query params (P1's
`Endpoint.params`), send a single quote `'` then a balanced `''` on ONE param at
a time and flag susceptibility **only via an error-based signal** (a DB-error
signature appears with `'` and is absent with `''`/baseline). `boolean_diff`
is DROPPED (red-team #6 — structurally noisy, unverifiable from single samples).

## Requirements
- Functional: per eligible endpoint with `params`, for up to K params (cap 3),
  GET `param='` and GET `param=''` (through SafeGetEngine, budget-counted). Emit
  `apitest.sqli.susceptible` (HIGH severity, confidence MEDIUM, observation
  POTENTIAL) ONLY when the `'` response trips a DB-error signature that the `''`
  and baseline responses do not. Evidence = the DB-error signature (never rows).
- Non-functional: GET-only; per-endpoint + global budget honored; no time-based;
  no data parsing/extraction.

## Architecture
- `modules/apitest/probes.py` (pure): `quote_variants(base_url, param)` →
  `(url_single, url_balanced)` appending `param='` / `param=''` to the query
  (uses P1 `Endpoint.params`, NOT parsing off a stripped URL — red-team #1);
  `error_based_signal(baseline_hit, single_hit, balanced_hit) -> bool`
  (true iff single_hit and not baseline_hit and not balanced_hit), where each
  `*_hit` = "a DB-error signature was found in that response". Pure + unit-tested.
- `module.py`: extend the P1 loop; run only for endpoints with `params`; reuse
  P1 DB-error signatures. No new response parsing.
- Encoding (red-team #10): the mock decodes `%27`; document that server-side
  decoding is required for the probe to reach the DB (a limitation, not a bug).

## Related Code Files
- Create: `modules/apitest/probes.py`, `tests/unit/test_apitest_probes.py`
- Modify: `modules/apitest/module.py` (sqli branch), `tests/fixtures/mock_site.py`
  (`/api/search?q=` returns a DB-error body ONLY when `q` contains an unbalanced
  quote; balanced/`''` returns benign JSON), `tests/integration/test_apitest.py`

## Implementation Steps (TDD — tests first)
1. **Test** `test_apitest_probes.py`: `quote_variants` builds correct `'`/`''`
   URLs from a base + param name (and handles an existing query); `error_based_
   signal` truth table (only single-hit-and-not-balanced → True).
2. **Test** integration: `active=True` on mock → `apitest.sqli.susceptible` fires
   for `/api/search` (param `q` from P1 capture); a param-less endpoint yields no
   sqli finding; finding is HIGH/MEDIUM/POTENTIAL; evidence holds the error
   signature, not returned data; a call-count test confirms ≤6 probes/endpoint.
3. Add the mock `/api/search` behavior (unbalanced `'` → DB error; else benign).
4. Implement `probes.py`, extend `module.py` → green.
5. ruff + mypy + pytest.

## Success Criteria
- [ ] `apitest.sqli.susceptible` fires on the injectable mock param (HIGH/MEDIUM/
      POTENTIAL); evidence = error signature only.
- [ ] No sqli finding on non-injectable or param-less endpoints (low FP).
- [ ] `boolean_diff` is NOT implemented; only the error-based path exists.
- [ ] GET-only; per-endpoint + global budget respected (call-count test).
- [ ] ruff + mypy clean; suite green.

## Risk Assessment
- Remaining FP surface is minimal: an actual DB-error signature is required. If a
  site returns generic 500s for both `'` and `''`, no signal → no finding (good).
- Encoding: if the server does not decode `%27`, the probe silently no-ops (no
  false positive; documented limitation).
