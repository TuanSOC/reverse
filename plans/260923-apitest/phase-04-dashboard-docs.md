---
phase: 4
title: Dashboard + Docs + gnddt.com run
status: completed
priority: P2
effort: 0.5d
dependencies:
  - 1
  - 2
  - 3
---

# Phase 4: Surface it (dashboard + CLI + docs) + validate on gnddt.com

## Overview
Expose the opt-in active testing safely in the UI/CLI, document the safety
boundary, then validate against the user-owned gnddt.com.

## Requirements
- Functional: CLI `scan --active` (already wired via config in P1 — confirm +
  help text with an authorized-only warning); dashboard "New Scan" gains an
  "Active API testing (authorized only)" checkbox → `StartScanRequest.active`.
- Docs: SECURITY.md (new opt-in active section, still no exploitation),
  THREAT_MODEL.md (note the active-probe boundary), MODULES.md (apitest row),
  CLI.md (`--active`). Authorized-only banner printed by the CLI when `--active`.
- Validate: run `webrecon scan https://gnddt.com/ --active` and report.

## Related Code Files
- Modify: `src/webrecon/cli/app.py` (`--active` flag + authorized banner),
  `src/webrecon/api/app.py` (`StartScanRequest.active` + pass to config),
  `src/webrecon/api/static/index.html` (checkbox),
  `docs/{SECURITY,THREAT_MODEL,MODULES,CLI}.md`
- Modify tests: `tests/integration/test_cli.py` (--active path),
  `tests/integration/test_api.py` (active flag accepted)
- Guard: `tests/unit/test_dashboard_js.py` already node-checks the UI JS.

## Implementation Steps (TDD — tests first)
1. **Test**: CLI `scan --active --no-db --modules ...` runs; API accepts
   `{"active": true}` in StartScanRequest.
2. Add CLI flag + banner; add dashboard checkbox (run the JS syntax guard).
3. Update the 4 docs.
4. Run full suite + ruff + mypy.
5. Restart server; `webrecon scan https://gnddt.com/ --active`; summarize findings.

## Success Criteria
- [ ] `--active` reachable from CLI and dashboard; default remains OFF/passive.
- [ ] CLI prints an authorized-only banner when `--active`.
- [ ] Dashboard JS still passes `node --check` guard.
- [ ] Docs updated; full suite green; ruff + mypy clean.
- [ ] gnddt.com `--active` run completed and reported.

## Risk Assessment
- UI making active testing too easy → checkbox label + banner state
  "authorized only"; default off; the safety contract from P1-P3 still applies.
- **Live gnddt.com run gate (red-team):** step 5 is safe ONLY because P1 shipped
  the verb deny-list (#2), observed-only probing (#4), and the SafeGetEngine
  GET-only wrapper (#3). Do not run `--active` live until P1's safety tests are
  green. Since this phase depends on [1,2,3], that holds by construction.
