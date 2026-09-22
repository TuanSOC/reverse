---
phase: 3
title: GraphQL Introspection (GET)
status: completed
priority: P2
effort: 0.5d
dependencies:
  - 1
---

# Phase 3: GraphQL introspection + verbose errors (GET only)

## Overview
For a discovered `/graphql`-style endpoint, send a read-only introspection query
via GET (`?query={__schema{types{name}}}`). If the schema is returned →
introspection is enabled (info leak). Also flag verbose GraphQL error responses.

## Requirements
- Functional: detect GraphQL endpoints (kind==graphql or url contains
  `/graphql`); GET the introspection query; if response JSON contains
  `data.__schema` → `apitest.graphql.introspection` (medium). If a GraphQL error
  block leaks stack/paths → reuse disclosure/db_error → contributes to existing
  findings. If the server rejects GET (405/400) → skip gracefully (no finding).
- Non-functional: GET only (no POST); introspection is read-only; scope-gated.

## Architecture
- `signatures.py`: add `INTROSPECTION_QUERY` constant + `is_introspection_result`
  (checks `data.__schema.types`). Pure detection helpers unit-tested.
- `module.py`: add graphql branch; single GET (via P1 `SafeGetEngine`) per
  graphql endpoint, budget-counted. Red-team #1 does not bite here — we
  *construct* the `?query={__schema...}` URL ourselves rather than relying on a
  stored (stripped) query. Verb deny-list / observed-only from P1 still apply.

## Related Code Files
- Modify: `src/webrecon/modules/apitest/{signatures.py,module.py}`,
  `tests/fixtures/mock_site.py` (`/graphql?query=` returns a mini `__schema` when
  the query asks for introspection), `tests/integration/test_apitest.py`,
  `tests/unit/test_apitest_signatures.py`

## Implementation Steps (TDD — tests first)
1. **Test**: `is_introspection_result` true for a `{"data":{"__schema":{...}}}`
   body, false otherwise; GET-only assertion for the graphql probe.
2. **Test** integration: `--active` on mock → `apitest.graphql.introspection`
   fires; a graphql endpoint that 405s on GET yields no finding (graceful skip).
3. Add mock `/graphql` route (GET introspection → schema; else benign).
4. Implement helpers + module branch.
5. ruff + mypy + pytest.

## Success Criteria
- [ ] `apitest.graphql.introspection` fires when GET introspection returns schema.
- [ ] GET-only; POST never used; graceful skip when GET unsupported.
- [ ] ruff + mypy clean; suite green.

## Risk Assessment
- Some servers only accept POST for GraphQL → GET introspection returns nothing →
  we simply do not flag (documented limitation, no false positive).
