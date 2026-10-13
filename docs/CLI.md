# WebRecon — CLI Reference

```bash
webrecon --help
```

## Commands (Phase 1)

### `webrecon version`
Print the WebRecon version.

### `webrecon init-db [--database-url URL]`
Create the local scan database schema. Defaults to
`sqlite+aiosqlite:///webrecon.db`. Parent directories are created automatically.

### `webrecon modules`
List registered scanner modules in dependency order (name, version, requires,
description).

### `webrecon serve [--host H] [--port P] [--database-url URL]`
Launch the dashboard (FastAPI) at `http://host:port` (default 127.0.0.1:8000).
Reads scans from the database and can start new scans with live progress.

### `webrecon scans [--database-url URL]`
List stored scans (id prefix, target, status, findings, created).

### `webrecon report SCAN_ID [--json P] [--html P] [--pdf P] [--database-url URL]`
Regenerate a report from a stored scan (accepts an 8-char id prefix). With no
export flag, prints a one-line risk summary.

### `webrecon ai SCAN_ID [--provider groq|stub] [--show] [--json P] [--database-url URL]`
Evidence-cited AI analysis of a stored scan (accepts an 8-char id prefix).
Uses Groq when `GROQ_API_KEY` is set (environment or a gitignored `.env`),
otherwise the deterministic offline stub. `--show` prints the latest stored
analysis without calling a provider. Every claim lists the evidence IDs it is
based on.

### `webrecon delete SCAN_ID [--yes]`
Delete a stored scan and every row it owns (findings, endpoints, assets, events,
AI analyses, screenshot…) plus an orphaned target. Irreversible; prompts for
confirmation unless `--yes`.

### Read commands — `findings`, `endpoints`, `assets`, `graph`
```
webrecon findings  [SCAN_ID] [--min-severity high] [--json]
webrecon endpoints [SCAN_ID] [--observation observed] [--json]
webrecon assets    [SCAN_ID] [--type script] [--json]
webrecon graph     [SCAN_ID] [--json]
```
Read a stored scan without re-scanning. `SCAN_ID` accepts a full id or an
8-char prefix; when omitted, the **latest** scan is used. Default output is a
table (`graph` prints node/edge counts); `--json` prints raw JSON for scripts.
All take `--database-url`.

## Extra `scan` options

| Option | Meaning |
|---|---|
| `--config PATH` | Load a base config from a TOML file (flags override). See `webrecon.example.toml`. |
| `--modules a,b` | Run only these modules (+ their deps). |
| `--allow-private` | Lab mode: permit private/loopback targets. |
| `--rate N` | Max requests/second. |
| `--concurrency N` | Max concurrent requests. |
| `--timeout S` | Per-request timeout. |
| `--no-robots` | Ignore robots.txt (authorized only). |
| `--probe` | Probe curated sensitive files (.git/.env/…), content-verified, GET-only. Authorized targets only. |
| `--active` | Active assessment (`apitest` + `active_verify` + `ratelimit` probe): DB errors, error-based SQLi susceptibility, data exposure, unauth access, GraphQL introspection, canary-confirmed open-redirect & reflected-XSS, and a hard-capped (≤12 GET) rate-limit enforcement probe. GET-only, observed endpoints only, budget-capped, detection/confirmation-level (no payload execution, no flooding, no bypass). Authorized targets only. |
| `--cookie "k=v; k2=v2"` | Authenticated scan: raw Cookie header sent **only to the target host** (never third parties) so the crawler/browser/active checks reach behind a login. Authorized targets only. |
| `--header "Name: value"` / `-H` | Extra request header (repeatable), e.g. `Authorization`. Sent **only to the target host**. |
| `--login-url U --login-user N --login-pass P` | Auto-login: a headless browser logs in and the session is reused. The login page must be on the target's own site and pass the SSRF guard; otherwise the scan continues unauthenticated. The password is never stored or reported. |
| `--ai` / `--ai-provider groq\|stub` | After the scan, run the AI analysis (sends normalized scan evidence to the provider). A bad provider or missing key fails fast (exit 2) before scanning. |
| `--html P` / `--pdf P` | Also write HTML / PDF report. |
| `--no-db` | Don't persist to the database. |

### `webrecon scan URL [options]`
Run a scan against a target you own or are authorized to test. The pipeline is
wired in the vertical-MVP phase; current options:

| Option | Default | Meaning |
|---|---|---|
| `--depth N` | 3 | Max crawl depth. |
| `--max-pages N` | 300 | Max pages to crawl. |
| `--browser` | off | Use the headless browser engine (P9). |
| `--json PATH` | — | Write a JSON report to PATH. |

Planned options as phases land: `--dns --tls --javascript --security --html
--pdf --concurrency --rate --scope-mode --allow-private`.

## Examples

```bash
webrecon init-db
webrecon scan https://example.com --depth 3 --max-pages 300
webrecon scan https://example.com --browser --json report.json
```

> Only scan assets you own or are explicitly authorized to test.
