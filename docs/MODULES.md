# WebRecon — Modules

Each scanner is an independent `ScannerModule` (see `ARCHITECTURE.md` and
`DEVELOPMENT.md`). This table is the planned module set and its status. Run
`webrecon modules` for the live registered list and resolved run order.

| Module | name | requires | Status | Purpose |
|---|---|---|---|---|
| Target | `target` | — | planned P2 | Normalize URL, parse parts, canonical URL, build `Target`. |
| Scope | `scope` | `target` | planned P2 | Initialize scope boundary from config + target. |
| HTTP | `http` | `scope` | planned P2 | Fetch base URL(s) via shared engine; headers, status, timing, redirects. |
| Redirect | (part of http) | `http` | planned P2 | Redirect chain, cross-domain / HTTPS→HTTP downgrade flags. |
| Crawler | `crawler` | `http` | planned P3 | Bounded BFS crawl, link/asset extraction, robots/sitemap. |
| DNS | `dns` | `target` | planned P4 | A/AAAA/CNAME/MX/NS/TXT/SOA/CAA, SPF/DMARC, dangling-CNAME flags. |
| TLS | `tls` | `target` | planned P4 | Certificate, chain, SAN, validity, protocol/HSTS checks. |
| Headers | `headers` | `http` | planned P4 | Security-header presence + explanation. |
| Cookies | `cookies` | `http` | planned P4 | Secure/HttpOnly/SameSite/Domain analysis (values masked). |
| CORS | `cors` | `http` | planned P4 | ACAO/credentials/methods combination flags. |
| Technology | `technology` | `http`, `crawler` | planned P5 | Fingerprint frontend/backend/infra with confidence + evidence. |
| JavaScript | `javascript` | `crawler` | planned P6 | Analyze public JS: endpoints/routes/config strings, source maps. |
| API | `api` | `crawler`, `javascript` | planned P7 | Endpoint discovery classified observed/referenced/potential. |
| Security | `security` | P4–P7 | planned P8 | Aggregate checks into findings with severity/confidence. |
| Browser | `browser` | `crawler` | planned P9 | Playwright render, network observation, screenshots. |

## Result contract (every module)

`ModuleResult`: `module`, `version`, `status`, `started_at`/`finished_at`,
`duration_ms`, `error`, `findings[]`, `evidence[]`, `data`, `stats`.

## Finding contract

`Finding`: `check_id`, `name`, `category`, `severity`, `confidence`,
`observation`, `description`, `impact`, `recommendation`, `references[]`,
`evidence[]` (≥1 required).
