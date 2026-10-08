---
title: Hardening + E2E verification + dashboard UX upgrade
description: >-
  Fix the 10 /code-review findings (2 security), verify every CLI command, API
  endpoint and dashboard view end-to-end, and upgrade the dashboard in place
  (home hub, clearer nav, EN/VI i18n, states, responsive, a11y).
status: completed
priority: P1
branch: master
tags: [security, bugfix, e2e, dashboard, ux, i18n]
blockedBy: []
blocks: []
created: '2026-10-08T00:00:00.000Z'
createdBy: 'ck:cook'
source: skill
---

## Requirements (agreed with user)

1. **Expected output**
   - 10 review findings fixed, each with a regression test.
   - E2E verification: every CLI command, every HTTP/WS API route, every
     dashboard section exercised against the mock site + a real browser; any
     breakage found is fixed.
   - Upgraded `src/webrecon/api/static/index.html`: Home hub with next steps,
     regrouped nav, EN/VI toggle (browser default, remembered), consistent
     loading/empty/error states, responsive down to phone width, a11y
     (focus-visible, keyboard nav, aria), visual polish.
2. **Acceptance criteria**
   - Password, cookies and auth headers never appear in `scans.config` or any
     report (masked as `***`); the rest of the config still persists.
   - Auto-login refuses a login URL blocked by the SSRF guard or on an
     unrelated site; the scan continues unauthenticated with an `auth` event.
   - Groq error bodies of any JSON shape → `AiError` (502 in API, message in
     CLI); scan reports are still written.
   - WebSocket `_done` is sent when the scan ends (AI runs afterwards); a bad
     AI provider is rejected *before* the scan starts (API 400 / CLI exit 2).
   - All 17 dashboard sections render with 0 console errors in EN and VI, at
     1440px and 390px widths; every interactive control reachable by keyboard.
   - ruff + mypy + pytest 100% green; `node --check` dashboard guard green.
3. **Out of scope**: big layout redesign, adding a frontend framework/build
   step, handoff cross-cutting items (CLI read commands, report sections),
   scanning real third-party targets.
4. **Constraints**: dashboard stays one self-contained file (no CDN); API and
   DB contracts additive only; detection-only; secrets never logged/persisted.
5. **Touchpoints**: `core/config.py`, `pipeline/orchestrator.py`,
   `reporting/json_report.py`, `engine/auto_login.py`, `api/app.py`,
   `api/queries.py`, `cli/app.py`, `intel/ai/analyzers.py`,
   `modules/javascript/{ast_js,module}.py`, `modules/api/module.py`,
   `api/static/index.html`.

## Phases

| # | Phase | Status |
|---|-------|--------|
| 1 | [Security fixes](phase-01-security-fixes.md) | done |
| 2 | [Correctness + robustness fixes](phase-02-correctness-fixes.md) | done |
| 3 | [E2E verification](phase-03-e2e-verification.md) | done |
| 4 | [Dashboard UX upgrade + i18n](phase-04-dashboard-ux.md) | done |
| 5 | [Review, docs, finalize](phase-05-review-finalize.md) | done |

## Risks
- `scans.config` masking: anything reading credentials back from the stored
  config breaks → grep readers first (db_report, queries).
- index.html is shared by every UI change → edit serially, run the JS guard
  after each edit.
- Auto-login redirects inside the browser are not re-checked (residual,
  documented).
