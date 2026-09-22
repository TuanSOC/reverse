---
title: apitest — Safe Active API/DB Assessment (opt-in)
description: >-
  Opt-in active API/DB assessment module: safe benign GET probes,
  detection-level only, no exploitation. TDD.
status: completed
priority: P2
branch: master
tags:
  - security
  - module
  - active-testing
  - api
  - dast
blockedBy: []
blocks: []
created: '2026-09-22T17:50:47.348Z'
createdBy: 'ck:plan'
source: skill
---

# apitest — Safe Active API/DB Assessment (opt-in)

## Overview

New scanner module `apitest` that actively tests in-scope discovered API
endpoints, emphasizing DB-related issues and leak/impact detection — but strictly
at **detection level, non-destructive, opt-in**. Approved design:
`docs/apitest-design.md`. TDD: each phase writes tests first to lock the safety
guarantees and detection logic before implementation.

### Hard safety contract (enforced in code, verified by tests)
*(hardened after red-team review — see "Red-team resolutions" below)*
- Runs ONLY when `config.active` is True (CLI `--active`, dashboard checkbox);
  otherwise the module returns `ModuleStatus.SKIPPED`. Default scan stays passive.
- **GET only, structurally enforced.** All requests go through a `SafeGetEngine`
  wrapper that RAISES on any method other than GET (unit-tested). We do not rely
  on module discipline. (OPTIONS dropped from the contract — unused.)
- **Only probe endpoints we actually observed** (provenance == `observed`) AND
  that are NOT action-verb endpoints. A verb deny-list
  (`delete|remove|drop|reset|logout|revoke|cancel|create|update|send|invite|
  purge|disable|deactivate|admin/write`) is applied first — because GET is NOT
  inherently safe (state-changing GETs exist). Referenced/potential (guessed)
  endpoints are never probed.
- **No data extraction.** SQLi = report *susceptibility* via an **error-based**
  signal only (a DB-error signature present with `'` and absent with `''`);
  the `boolean_diff` heuristic is dropped (structurally noisy). Never
  UNION/extraction; never parse/store returned rows; no time-based probing.
- **Budget enforced by a module-side counter**: ≤6 probes/endpoint, hard stop at
  ≤200 requests total (short-circuits the loop; emits a "partial/budget"
  note). The rate limiter throttles rate, not count — the counter is separate.
- Reuse the shared scope engine + SSRF guard (never bypass). In-scope only.
  Authorized-only banner in output + docs.

### Red-team resolutions (folded into phases)
1. **Param source (was fatal):** the `api` aggregator strips query params
   (`keep_query=False`) and `Endpoint` has no params → nothing to fuzz. Fix in
   P1: extend `EndpointAggregator.add()` to parse and union observed query-param
   NAMES into a new `Endpoint.params: set[str]`; P2 builds probes from those.
2. **State-changing GET / verb deny-list** → safety contract above (P1).
3. **SafeGetEngine method-forbidding wrapper** (P1).
4. **Observed-only probing** (P1).
5. **unauth_access corroboration:** only flag when the body ALSO trips
   data_exposure OR the path is sensitive (admin/internal/account/user); define
   "substantive JSON" concretely (array len ≥ 5 or object ≥ 5 keys) (P1).
6. **Drop boolean_diff; error-based SQLi only** (P2).
7. **data_exposure spec:** reuse `javascript.patterns.SECRETS` + key-name regex
   (`password|passwd|secret|token|api[_-]?key|ssn|authorization`) + record-count
   threshold; add a `mask_value()` helper (only `mask_email` exists) (P1).
8. **Dedup/precedence:** a DB-error body → `db_error` only; suppress the
   disclosure stack-trace contribution for the same evidence (P1).
9. **Budget counter** with a stop test (P1).
10. **`%27` encoding:** mock decodes it; probe asserted against a literal-quote
    behavior (P2).
11. **Safety tests:** (a) no non-GET ever sent, (b) referenced/out-of-scope not
    probed, (c) action-verb skipped, (d) budget halts, (e) secrets masked in
    serialized evidence (P1/P2).

### Reused infrastructure (DRY)
- `engine.HttpEngine` (scope + SSRF + rate + size caps) — the only request path.
- `modules/disclosure.py` — response body scanning for emails/PII/IPs/traces.
- `ctx.shared["api_endpoints"]` — endpoint inventory from the `api` module.
- Finding/Evidence models; register in `modules/__init__` + security `_UPSTREAM`.

## Phases

| Phase | Name | Status |
|-------|------|--------|
| 1 | [Core+DBError+DataExposure+Unauth](./phase-01-core-dberror-dataexposure-unauth.md) | Completed |
| 2 | [SQLi Susceptibility](./phase-02-sqli-susceptibility.md) | Completed |
| 3 | [GraphQL Introspection](./phase-03-graphql-introspection.md) | Completed |
| 4 | [Dashboard+Docs](./phase-04-dashboard-docs.md) | Completed |

Sequential: P1 establishes the safe request harness + module skeleton that
P2/P3 extend; P4 surfaces it (dashboard/docs) and re-scans gnddt.com.

## Acceptance (whole plan)
- `--active` on the mock vulnerable API → findings `apitest.db_error`,
  `apitest.data_exposure`, `apitest.auth.unauth_access`, `apitest.sqli.susceptible`,
  `apitest.graphql.introspection` fire.
- WITHOUT `--active` → module SKIPPED, zero extra requests.
- All requests GET/OPTIONS; a test asserts no non-idempotent method is ever sent.
- 190+ tests green; ruff + mypy clean. Docs (SECURITY/THREAT_MODEL/MODULES/CLI)
  updated. Post-build: `--active` run against gnddt.com (user-owned).

## Out of scope
Data dump/exploit (UNION), destructive methods, brute-force/credential attacks,
credentialed IDOR/BOLA (deferred), DoS/load, time-based SQLi, DB-port/network
scanning.

## Dependencies
None (no overlapping unfinished plans). Standalone module addition.
