# WebRecon — HTTP API

> **Status: planned (Phase P10).** The FastAPI backend + WebSocket live-progress
> channel are added when the dashboard lands. This file documents the intended
> surface so the frontend and CLI can be built against a stable contract.

## Planned REST endpoints

| Method | Path | Purpose |
|---|---|---|
| `POST` | `/api/scans` | Start a scan `{ url, config }` → `{ scan_id }`. |
| `GET` | `/api/scans` | List scans. |
| `GET` | `/api/scans/{id}` | Scan overview: status, target, module runs, risk summary. |
| `GET` | `/api/scans/{id}/findings` | Findings (filter by severity/category/confidence). |
| `GET` | `/api/scans/{id}/assets` | Asset inventory (filter by type). |
| `GET` | `/api/scans/{id}/endpoints` | Endpoints (observed/referenced/potential). |
| `GET` | `/api/scans/{id}/graph` | Relationship graph nodes/edges. |
| `GET` | `/api/scans/{id}/report?format=json\|html\|pdf` | Export. |
| `POST` | `/api/scans/{id}/cancel` | Cooperative cancellation. |

## Planned WebSocket

`WS /api/scans/{id}/events` — live module status, progress %, and redacted log
lines for the scan-progress view (§29).

All responses use the same schemas as `core/models.py` (findings, evidence,
module results) so CLI, API, and reports agree byte-for-byte.
