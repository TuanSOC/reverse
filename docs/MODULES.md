# WebRecon — Modules

Each scanner is an independent `ScannerModule` (see `ARCHITECTURE.md` and
`DEVELOPMENT.md`). This table is the planned module set and its status. Run
`webrecon modules` for the live registered list and resolved run order.

| Module | name | requires | Status | Purpose |
|---|---|---|---|---|
| Target | `target` | — | ✅ P2 | Normalize URL, parse parts, SSRF pre-check, build `TargetInfo`. |
| Scope | `scope` | `target` | ✅ P2 | Initialize scope boundary from config + target. |
| HTTP | `http` | `scope` | ✅ P2 | Fetch base URL via shared engine; status, timing, redirects, transport findings. |
| Redirect | (part of `http`) | `http` | ✅ P2 | Redirect chain, cross-domain / HTTPS→HTTP downgrade flags. |
| Crawler | `crawler` | `http` | ✅ P3 | Bounded BFS crawl; links/assets/forms/metadata; robots + sitemap; crawl graph edges. |
| DNS | `dns` | `target` | ✅ P4 | A/AAAA/CNAME/MX/NS/TXT/SOA/CAA, SPF/DMARC posture, dangling-CNAME flags (skips IP literals). |
| TLS | `tls` | `target` | ✅ P4 | Certificate, SAN, validity, hostname match, self-signed, protocol (SSRF-guarded, skips no-TLS hosts). |
| Headers | `headers` | `http` | ✅ P4 | Security-header presence + explanation; version-disclosure headers. |
| Cookies | `cookies` | `http` | ✅ P4 | Secure/HttpOnly/SameSite/Domain analysis (values masked). |
| CORS | `cors` | `http` | ✅ P4 | ACAO/credentials/null combination flags (passive). |
| Technology | `technology` | `http`, `crawler` | ✅ P5 | Signature-based fingerprint (headers/cookies/HTML/scripts/meta) with confidence + version + evidence. |
| JavaScript | `javascript` | `crawler` | ✅ P6 | Download in-scope JS; extract endpoints/ws/graphql/analytics/cloud; masked secret scan; exposed source-map detection. |
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
