# Phase 2 — Correctness + robustness fixes (TDD)

| Review # | Fix | Test |
|---|---|---|
| 3 | `_error_message`: tolerate any JSON shape (`{"error": "str"}`, list, string) | MockTransport 429 with string error → AiError |
| 4 | API: validate provider in `start()` (400) and send `_done` before AI; AI status via progress event `ai`. CLI: validate `--ai-provider` before scanning (exit 2) | API test bad provider → 400; manager test ordering |
| 5 | `extract_calls`: on timeout `proc.kill()` + `await proc.wait()` | fake slow node script → process gone |
| 6 | `_analyze_reconstructed`: run per-file `extract_calls` concurrently, `Semaphore(4)` | existing sourcemap tests stay green |
| 7 | `rank_login_fields`: `is not None` instead of `or` | idx-0 hinted email + captcha + password → 0 |
| 9 | api module: skip AST URLs with a placeholder in the base/host (leading `{`); keep path templates | `{apiBase}/users` not added; `/api/users/{id}` kept |
| 10 | `_SESSION_COOKIE`: anchored names (`session`, `sess`, `sid`, `*_session`, `jsessionid`, `phpsessid`, `connect.sid`, `auth`, `token` exact-ish); drop `csrftoken`, substring `sid` | table test: visid_incap_1 / csrftoken → False; PHPSESSID / laravel_session → True |
