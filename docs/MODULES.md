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
| API | `api` | `crawler`, `javascript` | ✅ P7 | Consolidate endpoints (crawler/JS/sitemap) → observed/referenced/potential; REST/GraphQL/WebSocket; no probing. |
| Exposure | `exposure` | `http` | ✅ | security.txt (RFC 9116), risky HTTP methods (OPTIONS), opt-in sensitive-file probes (.git/.env/… — `--probe`, content-verified). |
| Subdomains | `subdomains` | target/tls/crawler/javascript/api | ✅ | Passive subdomain discovery from cert SAN + links + JS + endpoints, then resolve; flags unresolvable/dangling. No brute force. |
| API test | `apitest` | `api` | ✅ (opt-in `--active`) | Safe active API/DB assessment: DB-error leakage, error-based SQLi susceptibility, sensitive-data exposure, unauth access, GraphQL introspection. GET-only, observed-endpoints-only, budget-capped, detection-level (no exploitation). |
| DOM security | `dom_security` | `javascript` | ✅ v0.2 | Static client-side heuristics over retained JS: DOM XSS source→sink patterns + unguarded prototype-pollution deep-merge loops (POTENTIAL, code-snippet evidence). |
| Forms & auth | `forms_auth` | `crawler` | ✅ v0.2 | Classify forms (login/register/reset/search/contact/payment); flag missing CSRF token, password over cleartext transport, autocomplete hygiene. |
| IP intelligence | `ip_intel` | `target`, `dns` | ✅ v0.3 | Reverse DNS (PTR), ASN/AS-name/registry (Team Cymru DNS), geolocation (public API via `ctx.http`), cloud/CDN classification, and CDN origin-IP exposure. Skips private/lab IPs. |
| Secret leak | `secret_leak` | `javascript`, `crawler` | ✅ v0.3 | Scan JS + all crawled HTML for hardcoded AWS/Google/GitHub/Stripe/Slack/PEM/JWT credentials. Evidence is always **masked** (first-4/last-4); example keys excluded. |
| Active verify | `active_verify` | `api` | ✅ (opt-in `--active`) | Confirms open-redirect & reflected-XSS candidates with **benign canaries** (unresolvable `.invalid` redirect target; inert `<xss>` marker). GET-only, budget-capped, no payload execution / data extraction. Upgrades findings potential→observed. |
| Security | `security` | headers/cookies/cors/tls/dns/technology/javascript/api/exposure/apitest/dom_security/forms_auth/ip_intel/secret_leak/active_verify | ✅ P8 | Cross-module rules (mixed content, outdated tech, dir listing) + deterministic risk classification. |
| Browser | `browser` | `scope` | ✅ P9 | Opt-in Playwright render; XHR/fetch/WebSocket observation; scope-enforced in-browser; screenshots. |

## Result contract (every module)

`ModuleResult`: `module`, `version`, `status`, `started_at`/`finished_at`,
`duration_ms`, `error`, `findings[]`, `evidence[]`, `data`, `stats`.

## Finding contract

`Finding`: `check_id`, `name`, `category`, `severity`, `confidence`,
`observation`, `description`, `impact`, `recommendation`, `references[]`,
`evidence[]` (≥1 required).
