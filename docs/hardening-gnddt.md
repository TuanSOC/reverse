# Hardening guide — gnddt.com

Remediation for the WebRecon scan of `https://gnddt.com/` (risk: medium, 9
findings — all configuration/hardening gaps, no exploitable vulnerabilities
found). Stack: Cloudflare (edge) + ASP.NET (origin). Apply headers in **one**
place only (edge *or* origin — duplicate headers cause errors). Test before
tightening.

> Scan again from the dashboard after applying — the header/DMARC findings
> should disappear and the risk should drop to Low/Informational.

---

## 1. Security headers

### Option A — Cloudflare (fastest)

**HSTS** → SSL/TLS → Edge Certificates → *HTTP Strict Transport Security*:
- Max-Age: `15552000` (6 months)
- Include subdomains: enable **only if** every subdomain (incl. `api.gnddt.com`)
  is HTTPS; otherwise leave off
- Preload: leave OFF until stable for a few weeks
- No-Sniff header: on

**Other headers** → Rules → Transform Rules → Modify Response Header → *Set*:

| Header | Value |
|---|---|
| `X-Content-Type-Options` | `nosniff` |
| `X-Frame-Options` | `SAMEORIGIN` |
| `Referrer-Policy` | `strict-origin-when-cross-origin` |
| `Permissions-Policy` | `camera=(), microphone=(), geolocation=(), interest-cohort=()` |
| `Cross-Origin-Opener-Policy` | `same-origin-allow-popups` |
| `Cross-Origin-Resource-Policy` | `same-site` |

**CSP — test as Report-Only first** (site uses Angular + jQuery; a strict CSP
breaks easily). Header `Content-Security-Policy-Report-Only`:

```
default-src 'self'; script-src 'self' 'unsafe-inline' 'unsafe-eval' https://ajax.googleapis.com; style-src 'self' 'unsafe-inline'; img-src 'self' data: https:; connect-src 'self' https://api.gnddt.com https://www.googleapis.com; font-src 'self' data:; frame-ancestors 'self'; base-uri 'self'; form-action 'self'
```

Run a few days, watch the console for "would block", then rename the header to
`Content-Security-Policy` and progressively remove `'unsafe-inline'`/
`'unsafe-eval'` using nonces (see §3).

### Option B — ASP.NET origin (`web.config`)

```xml
<system.webServer>
  <httpProtocol>
    <customHeaders>
      <add name="Strict-Transport-Security" value="max-age=15552000; includeSubDomains" />
      <add name="X-Content-Type-Options" value="nosniff" />
      <add name="X-Frame-Options" value="SAMEORIGIN" />
      <add name="Referrer-Policy" value="strict-origin-when-cross-origin" />
      <add name="Permissions-Policy" value="camera=(), microphone=(), geolocation=()" />
      <add name="Cross-Origin-Opener-Policy" value="same-origin-allow-popups" />
      <add name="Cross-Origin-Resource-Policy" value="same-site" />
      <add name="Content-Security-Policy-Report-Only" value="default-src 'self'; script-src 'self' 'unsafe-inline' 'unsafe-eval' https://ajax.googleapis.com; style-src 'self' 'unsafe-inline'; img-src 'self' data: https:; connect-src 'self' https://api.gnddt.com; frame-ancestors 'self'; base-uri 'self'; form-action 'self'" />
    </customHeaders>
  </httpProtocol>
</system.webServer>
```

---

## 2. DMARC + email

**DMARC** — Cloudflare → DNS → add record:
- Type `TXT`, Name `_dmarc`, TTL Auto
- Content:
  ```
  v=DMARC1; p=none; rua=mailto:dmarc@gnddt.com; ruf=mailto:dmarc@gnddt.com; fo=1; adkim=s; aspf=s; pct=100
  ```
- `p=none` = monitor only. After 2–4 weeks reading `rua` reports, raise to
  `p=quarantine` then `p=reject`. Needs a mailbox for reports (or a free
  aggregator like dmarc.postmarkapp.com).

**SPF** — already `v=spf1 include:spf.efwd.registrar-servers.com ~all`. Once all
legitimate senders are covered, tighten `~all` → `-all`.

**DKIM** — depends on how you actually *send* mail. If via a provider (Google
Workspace, Zoho, SendGrid…), add that provider's DKIM selector record.

---

## 3. Strict CSP with per-request nonce (ASP.NET Core)

Removes `'unsafe-inline'` for scripts — the biggest CSP weakness. Every request
gets a random nonce; inline `<script>` tags must carry it.

**Middleware** (`CspNonceMiddleware.cs`):

```csharp
using System.Security.Cryptography;

public sealed class CspNonceMiddleware
{
    private readonly RequestDelegate _next;
    public CspNonceMiddleware(RequestDelegate next) => _next = next;

    public async Task Invoke(HttpContext ctx)
    {
        var nonce = Convert.ToBase64String(RandomNumberGenerator.GetBytes(16));
        ctx.Items["csp-nonce"] = nonce;

        var csp =
            $"default-src 'self'; " +
            $"script-src 'self' 'nonce-{nonce}' https://ajax.googleapis.com; " +
            "style-src 'self' 'unsafe-inline'; " +           // Angular often needs inline styles
            "img-src 'self' data: https:; " +
            "connect-src 'self' https://api.gnddt.com https://www.googleapis.com; " +
            "font-src 'self' data:; frame-ancestors 'self'; base-uri 'self'; form-action 'self'";

        ctx.Response.Headers["Content-Security-Policy"] = csp;
        await _next(ctx);
    }
}
```

**Register** (`Program.cs`, before `app.MapControllers()`):

```csharp
app.UseMiddleware<CspNonceMiddleware>();
```

**Use the nonce in views** (Razor) for any inline script:

```cshtml
@{ var nonce = Context.Items["csp-nonce"] as string; }
<script nonce="@nonce">
  // inline JS here is now allowed by CSP
</script>
```

Notes:
- External scripts (`<script src="…">`) don't need the nonce, but their host
  must be in `script-src`. Move inline blocks to external files where possible.
- `style-src 'unsafe-inline'` is kept because Angular injects inline styles;
  remove it later with hashed styles if you want a fully strict policy.
- Classic ASP.NET MVC: do the same in an `ActionFilter`/`HttpModule` — generate
  the nonce into `HttpContext.Items`, set the header, emit `nonce="..."`.

---

## 4. Verify

1. Re-scan `https://gnddt.com/` from the WebRecon dashboard (Browser mode on).
2. Expect `headers.*` and `dns.dmarc.missing` findings to clear.
3. Check the live headers: `curl -sI https://gnddt.com | grep -iE 'strict-transport|content-security|x-frame|x-content|referrer|permissions|cross-origin'`.
