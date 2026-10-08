# WebRecon — HTTP API

Served by `webrecon serve` (FastAPI, default `http://127.0.0.1:8000`). The
dashboard at `/` is a client of exactly these routes. All responses are JSON
unless noted; secret values (cookies, auth headers, passwords, matched
credentials) are always masked.

## Scans

| Method | Path | Purpose |
|---|---|---|
| `GET` | `/api/scans` | List scans, newest first: `[{id, target, status, created_at, finished_at, findings}]`. |
| `POST` | `/api/scans` | Start a scan in the background → `{scan_id}`. Body: `url`, `depth`, `max_pages`, `scope_mode`, `browser`, `allow_private`, `active`, `probe`, `cookie`, `headers[]`, `login_url`/`login_user`/`login_pass`, `ai`, `ai_provider`. A bad `ai_provider` (or `groq` without a key) → `400` before anything starts. |
| `POST` | `/api/scans/{id}/cancel` | Cooperative cancellation → `{cancelled: bool}`. |
| `WS` | `/api/scans/{id}/events` | Live progress `{module, index, total, status}`; ends with `{module: "_done", status}`. Sent as soon as the scan ends — a requested AI analysis runs afterwards. |

## Scan data (`/api/scans/{id}/…`)

| Path | Returns |
|---|---|
| `` (overview) | Status, target, risk level, findings by severity, module runs, technologies, IP intel. `404` if unknown. |
| `findings` | Findings with evidence, sorted by severity. |
| `endpoints` | Endpoints with `meta.params` (classified parameters), `meta.discovery_status`, sources. |
| `assets`, `pages`, `forms`, `technologies`, `dns`, `certificates` | Inventories. |
| `js` | JS Explorer rows: hash, size, frameworks, regex + AST endpoints, source-map status, secret *count*. |
| `graph` | Unified asset graph `{nodes:[{id,label,type,source,confidence,props}], edges:[{source,target,relation}]}`. |
| `attack-surface` | Hierarchical tree (domain → web surface / assets / tech / infra) with per-branch `max_severity` and `finding_count`. |
| `auth-flow` | Detection-only auth model: `kind`, `confidence`, `steps` (English narrative) with parallel `step_keys` (stable ids: `form`, `login`, `session`, `identity`, `logout`, `redirect`, `authorize`, `callback`, `token`), auth endpoints, login-form / session-cookie flags. |
| `timeline?kind=` | Ordered scan events (`scan`, `module`, `auth`, `discovered`, `observed`, `finding`). |
| `diff?against={other_id}` | Added/removed endpoints, technologies and findings between two scans. |
| `screenshot` | PNG (browser mode only), else `404`. |
| `report.{json\|html\|pdf}?min_severity=` | Export; `pdf` returns `503` when no PDF engine is available, unknown format → `400`. |

## AI analysis

| Method | Path | Purpose |
|---|---|---|
| `GET` | `/api/scans/{id}/ai` | `{analysis, groq_available, running}` — latest stored analysis (or `null`), whether a Groq key is configured (boolean only), and whether a post-scan analysis is in progress. |
| `POST` | `/api/scans/{id}/ai?provider=groq\|stub` | Run and store an analysis. `400` bad provider / missing key, `404` unknown scan, `502` provider error. |

An analysis is `{provider, model, created_at, app_summary, sections:{components,
attack_surface, auth_apis, static_vs_observed, gaps}, rejected_claims, evidence}`.
Every claim carries `evidence` IDs that resolve in the `evidence` snapshot;
claims citing nothing valid are dropped and counted in `rejected_claims`.
