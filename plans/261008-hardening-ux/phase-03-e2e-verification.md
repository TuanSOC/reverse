# Phase 3 — E2E verification

Scratch harness (not committed) on the mock site:
1. CLI: `version`, `init-db`, `modules`, `scan` (+`--json/--html/--pdf`, `--ai
   --ai-provider stub`), `scans`, `report` (all formats, prefix id), `ai`
   (`--provider stub`, `--show`, `--json`), `serve` (starts, `/` 200).
2. API: every GET route for a scan (+404/400 paths), POST /api/scans → WS
   progress → `_done`, POST cancel, POST ai, report.{json,html,pdf},
   min_severity filter, diff.
3. Browser: all sections, drawer open/close, filters, palette ⌘K, theme
   toggle, New Scan dialog end-to-end (start scan from UI → progress →
   result), console errors = 0.
Output: checklist with pass/fail; every fail → fix + regression test.
