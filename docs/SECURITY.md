# WebRecon — Security Policy & Safety Boundary

## Authorized use only

WebRecon is built exclusively for:

- assets you **own**,
- **authorized** penetration testing (written scope/permission),
- security research on systems you are **permitted** to test,
- local labs and CTF environments.

Using it against systems you do not own or have no permission to test may be
illegal. You are responsible for staying within your authorization.

## What WebRecon deliberately does NOT do (§42)

The following are **out of scope by design** and will not be implemented:

- brute-force / credential stuffing / password spraying
- authentication bypass or session/token theft
- automated exploitation or destructive actions
- malware, persistence, stealth, or evasion
- denial of service or load/stress generation
- mass scanning of arbitrary internet targets

Dual-use capabilities are intentionally kept at the **detection / assessment /
evidence** level. For example, CORS and source-map checks *report* a
misconfiguration with evidence; they never *exploit* it.

## Safety controls built into the tool

| Control | Where | Purpose |
|---|---|---|
| SSRF guard | engine (P2) | Blocks loopback/private/link-local/metadata IPs, non-http(s) schemes; re-checks the resolved IP, not just the hostname. Lab targets require explicit `allow_private_targets`. |
| Scope engine | engine (P2) | Every request is gated by same-origin/domain/subdomain + path rules before it is sent. |
| Rate limiting | engine (P2) | Conservative defaults (≤ a few req/s), per-host concurrency, 429 backoff. |
| Response size cap | HTTP engine | 10 MiB hard cap; decompression-bomb protection to prevent memory exhaustion. |
| Secret redaction | `core/logging.py` | Authorization/cookie/token values are never written to logs. |
| Cookie masking | UI/reports (later) | Sensitive cookie values are masked, never shown in full. |
| No code execution | whole tool | Downloaded JS/HTML is parsed/analyzed statically; JS only ever runs inside the sandboxed Playwright browser, never in the tool process. |
| Strict schemas | `core/models.py` | `extra="forbid"` on all models; report output is escaped to prevent stored XSS. |

## Tool-hardening checklist (tracked to Phase P13)

- [x] Response size + timeout caps (HTTP engine)
- [x] Secret redaction in logs
- [x] SSRF guard with resolved-IP recheck on every redirect hop (P2)
- [x] Scope gate on every request incl. redirect targets (P2)
- [x] Response-size cap enforced by streamed, capped reads (P2)
- [x] HTML report output escaping (Jinja2 autoescape) — stored-XSS test
- [x] SQL parameterization (SQLAlchemy ORM throughout; no string SQL)
- [x] Malformed / duplicate headers do not crash (hardening test)
- [x] Malformed HTML does not crash the parser (hardening test)
- [x] JS is never executed in-process; only inside the sandboxed browser
- [x] Secrets masked in logs, evidence, API, and reports (leak tests)
- [x] Failing/timing-out module is isolated (does not abort the scan)
- [x] Export writes only to an explicit path (never derived from target data)
- [~] Decompression-bomb: bounded by the decoded-size cap; content-encoding-aware
      limit still a possible refinement

## Reporting a vulnerability in WebRecon itself

This is a local single-user tool in early development. If you find a security
issue in the tool, open an issue describing the impact and a reproduction.
