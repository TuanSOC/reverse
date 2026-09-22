"""Curated technology signatures (§10).

Each signature ties one observable signal (a header, cookie name, HTML snippet,
script URL, or meta-generator value) to a technology, with a base confidence and
optional version-capturing regex group. Signatures are intentionally
conservative — we would rather miss a detection than assert a wrong one. The
fingerprint engine aggregates multiple signals for the same technology and only
raises confidence when independent sources agree.
"""

from __future__ import annotations

from dataclasses import dataclass

from ...core.enums import Confidence

# Signal sources.
HEADER = "header"
COOKIE = "cookie"
HTML = "html"
SCRIPT = "script"
META = "meta_generator"


@dataclass(frozen=True)
class Signature:
    tech: str
    category: str
    source: str
    pattern: str  # regex (case-insensitive)
    confidence: Confidence
    header: str | None = None  # for HEADER source: which header to inspect
    version_group: int | None = None  # regex group index capturing a version


# Categories: frontend, backend, infra, cdn, cms, analytics, server, language.
SIGNATURES: tuple[Signature, ...] = (
    # --- servers -----------------------------------------------------------
    Signature("Nginx", "server", HEADER, r"nginx(?:/([\d.]+))?", Confidence.HIGH, "server", 1),
    Signature("Apache", "server", HEADER, r"apache(?:/([\d.]+))?", Confidence.HIGH, "server", 1),
    Signature("Microsoft-IIS", "server", HEADER, r"microsoft-iis(?:/([\d.]+))?",
              Confidence.HIGH, "server", 1),
    Signature("LiteSpeed", "server", HEADER, r"litespeed", Confidence.HIGH, "server"),
    # --- languages / frameworks (headers) ----------------------------------
    Signature("PHP", "language", HEADER, r"php(?:/([\d.]+))?", Confidence.HIGH,
              "x-powered-by", 1),
    Signature("ASP.NET", "backend", HEADER, r".+", Confidence.HIGH, "x-aspnet-version"),
    Signature("ASP.NET", "backend", HEADER, r"asp\.net", Confidence.HIGH, "x-powered-by"),
    Signature("Express", "backend", HEADER, r"express", Confidence.HIGH, "x-powered-by"),
    Signature("Next.js", "frontend", HEADER, r".+", Confidence.MEDIUM, "x-nextjs-cache"),
    # --- CDN / hosting (headers) -------------------------------------------
    Signature("Cloudflare", "cdn", HEADER, r".+", Confidence.HIGH, "cf-ray"),
    Signature("Cloudflare", "cdn", HEADER, r"cloudflare", Confidence.HIGH, "server"),
    Signature("Vercel", "hosting", HEADER, r".+", Confidence.HIGH, "x-vercel-id"),
    Signature("Netlify", "hosting", HEADER, r".+", Confidence.HIGH, "x-nf-request-id"),
    Signature("Fastly", "cdn", HEADER, r"fastly", Confidence.MEDIUM, "x-served-by"),
    Signature("Amazon S3", "hosting", HEADER, r"amazons3", Confidence.MEDIUM, "server"),
    Signature("Amazon CloudFront", "cdn", HEADER, r"cloudfront", Confidence.MEDIUM, "via"),
    Signature("Akamai", "cdn", HEADER, r".+", Confidence.MEDIUM, "x-akamai-transformed"),
    # --- cookies ------------------------------------------------------------
    Signature("PHP", "language", COOKIE, r"^phpsessid$", Confidence.HIGH),
    Signature("Laravel", "backend", COOKIE, r"^laravel_session$", Confidence.HIGH),
    Signature("Laravel", "backend", COOKIE, r"^xsrf-token$", Confidence.LOW),
    Signature("Django", "backend", COOKIE, r"^csrftoken$", Confidence.MEDIUM),
    Signature("Express", "backend", COOKIE, r"^connect\.sid$", Confidence.MEDIUM),
    Signature("ASP.NET", "backend", COOKIE, r"^asp\.net_sessionid$", Confidence.HIGH),
    Signature("Java", "language", COOKIE, r"^jsessionid$", Confidence.MEDIUM),
    Signature("Ruby on Rails", "backend", COOKIE, r"^_session_id$", Confidence.LOW),
    Signature("Flask", "backend", COOKIE, r"^session$", Confidence.LOW),
    Signature("Shopify", "cms", COOKIE, r"^_shopify_", Confidence.HIGH),
    Signature("WooCommerce", "cms", COOKIE, r"^woocommerce_", Confidence.HIGH),
    # --- HTML body ----------------------------------------------------------
    Signature("Next.js", "frontend", HTML, r"__NEXT_DATA__", Confidence.HIGH),
    Signature("Next.js", "frontend", HTML, r"/_next/static", Confidence.HIGH),
    Signature("Nuxt.js", "frontend", HTML, r"__NUXT__|/_nuxt/", Confidence.HIGH),
    Signature("React", "frontend", HTML, r"data-reactroot|data-reactid", Confidence.MEDIUM),
    Signature("Vue.js", "frontend", HTML, r"data-v-[0-9a-f]{8}", Confidence.MEDIUM),
    Signature("Angular", "frontend", HTML, r"ng-version=\"([\d.]+)\"", Confidence.HIGH, None, 1),
    Signature("Svelte", "frontend", HTML, r"/_app/immutable/", Confidence.MEDIUM),
    Signature("WordPress", "cms", HTML, r"/wp-content/|/wp-includes/", Confidence.HIGH),
    Signature("Drupal", "cms", HTML, r'data-drupal-|Drupal.settings', Confidence.HIGH),
    Signature("Google Analytics", "analytics", HTML, r"google-analytics\.com/analytics\.js|gtag\(",
              Confidence.MEDIUM),
    # --- script URLs --------------------------------------------------------
    Signature("jQuery", "frontend", SCRIPT, r"jquery(?:[-.](\d[\d.]+))?", Confidence.MEDIUM,
              None, 1),
    Signature("Next.js", "frontend", SCRIPT, r"/_next/", Confidence.HIGH),
    Signature("WordPress", "cms", SCRIPT, r"/wp-content/|/wp-includes/", Confidence.HIGH),
    # --- meta generator -----------------------------------------------------
    Signature("WordPress", "cms", META, r"wordpress\s*([\d.]+)?", Confidence.HIGH, None, 1),
    Signature("Drupal", "cms", META, r"drupal\s*([\d.]+)?", Confidence.HIGH, None, 1),
    Signature("Joomla", "cms", META, r"joomla", Confidence.HIGH),
    Signature("Hugo", "cms", META, r"hugo\s*([\d.]+)?", Confidence.HIGH, None, 1),
    Signature("Ghost", "cms", META, r"ghost\s*([\d.]+)?", Confidence.HIGH, None, 1),
    Signature("Wix", "cms", META, r"wix\.com", Confidence.HIGH),
    Signature("Squarespace", "cms", META, r"squarespace", Confidence.HIGH),
    Signature("Gatsby", "frontend", META, r"gatsby\s*([\d.]+)?", Confidence.HIGH, None, 1),
    Signature("Astro", "frontend", META, r"astro\s*v?([\d.]+)?", Confidence.HIGH, None, 1),
    Signature("Docusaurus", "frontend", META, r"docusaurus\s*v?([\d.]+)?", Confidence.HIGH, None, 1),
    # --- extra HTML/body signatures ----------------------------------------
    Signature("Tailwind CSS", "frontend", HTML, r"tailwind|--tw-", Confidence.LOW),
    Signature("Bootstrap", "frontend", HTML, r"bootstrap(?:[.-]([\d.]+))?", Confidence.LOW, None, 1),
    Signature("Gatsby", "frontend", HTML, r"___gatsby|/page-data/", Confidence.HIGH),
    Signature("Remix", "frontend", HTML, r"__remixContext|/build/_shared/", Confidence.HIGH),
    Signature("Astro", "frontend", HTML, r"astro-island|/_astro/", Confidence.HIGH),
    Signature("SvelteKit", "frontend", HTML, r"__sveltekit|/_app/immutable/", Confidence.HIGH),
    Signature("Shopify", "cms", HTML, r"cdn\.shopify\.com|Shopify\.theme", Confidence.HIGH),
    Signature("Webflow", "cms", HTML, r"webflow\.js|data-wf-", Confidence.HIGH),
    Signature("HubSpot", "analytics", HTML, r"js\.hs-scripts\.com|hubspot", Confidence.MEDIUM),
    Signature("reCAPTCHA", "security", HTML, r"google\.com/recaptcha|grecaptcha", Confidence.HIGH),
    Signature("Cloudflare Turnstile", "security", HTML, r"challenges\.cloudflare\.com/turnstile",
              Confidence.HIGH),
    Signature("Google Tag Manager", "analytics", HTML, r"googletagmanager\.com/gtm", Confidence.HIGH),
    Signature("Google Analytics 4", "analytics", HTML, r"gtag/js\?id=G-|googletagmanager\.com/gtag",
              Confidence.MEDIUM),
    Signature("Hotjar", "analytics", HTML, r"static\.hotjar\.com|hjSetting", Confidence.HIGH),
    Signature("Segment", "analytics", HTML, r"cdn\.segment\.com|analytics\.track", Confidence.MEDIUM),
    Signature("Sentry", "monitoring", HTML, r"sentry-cdn\.com|Sentry\.init", Confidence.HIGH),
    Signature("Stripe", "payment", HTML, r"js\.stripe\.com", Confidence.HIGH),
    Signature("PayPal", "payment", HTML, r"paypal\.com/sdk/js|paypalobjects", Confidence.HIGH),
    Signature("Font Awesome", "frontend", HTML, r"font-?awesome|fa-[a-z]", Confidence.LOW),
    # --- extra script-URL signatures ---------------------------------------
    Signature("Lodash", "frontend", SCRIPT, r"lodash(?:[.-]([\d.]+))?", Confidence.MEDIUM, None, 1),
    Signature("Moment.js", "frontend", SCRIPT, r"moment(?:[.-]([\d.]+))?\.min\.js", Confidence.MEDIUM,
              None, 1),
    Signature("D3.js", "frontend", SCRIPT, r"d3(?:[.-]v?([\d.]+))?\.min\.js", Confidence.MEDIUM, None, 1),
    Signature("Three.js", "frontend", SCRIPT, r"three(?:[.-]([\dr.]+))?\.min\.js", Confidence.MEDIUM,
              None, 1),
    Signature("jQuery UI", "frontend", SCRIPT, r"jquery-ui(?:[.-]([\d.]+))?", Confidence.MEDIUM, None, 1),
    Signature("Vue.js", "frontend", SCRIPT, r"vue(?:[.-]([\d.]+))?(?:\.min)?\.js", Confidence.MEDIUM,
              None, 1),
    Signature("Alpine.js", "frontend", SCRIPT, r"alpinejs|cdn\.jsdelivr\.net/npm/alpinejs",
              Confidence.MEDIUM),
    Signature("htmx", "frontend", SCRIPT, r"htmx(?:\.org)?(?:[.-]([\d.]+))?\.min\.js", Confidence.MEDIUM,
              None, 1),
    # --- extra header signatures -------------------------------------------
    Signature("OpenResty", "server", HEADER, r"openresty(?:/([\d.]+))?", Confidence.HIGH, "server", 1),
    Signature("Caddy", "server", HEADER, r"caddy", Confidence.HIGH, "server"),
    Signature("Gunicorn", "server", HEADER, r"gunicorn(?:/([\d.]+))?", Confidence.HIGH, "server", 1),
    Signature("Werkzeug", "server", HEADER, r"werkzeug(?:/([\d.]+))?", Confidence.HIGH, "server", 1),
    Signature("Kestrel", "server", HEADER, r"kestrel", Confidence.HIGH, "server"),
    Signature("Google Frontend", "hosting", HEADER, r"gws|google frontend", Confidence.MEDIUM, "server"),
    Signature("GitHub Pages", "hosting", HEADER, r"github\.com", Confidence.MEDIUM, "server"),
    Signature("Varnish", "cdn", HEADER, r".+", Confidence.MEDIUM, "x-varnish"),
    Signature("Envoy", "server", HEADER, r"envoy", Confidence.MEDIUM, "server"),
    Signature("Uvicorn", "server", HEADER, r"uvicorn", Confidence.HIGH, "server"),
    Signature("Strapi", "cms", HEADER, r"strapi", Confidence.HIGH, "x-powered-by"),
    Signature("Spring Boot", "backend", HEADER, r".+", Confidence.HIGH, "x-application-context"),
    # --- v0.2 modern frameworks / auth / CMS (HTML + script) ---------------
    Signature("SolidJS", "frontend", HTML, r"_\$HY|solid-js|data-hk=", Confidence.MEDIUM),
    Signature("Chakra UI", "frontend", HTML, r"chakra-ui|class=\"chakra-", Confidence.MEDIUM),
    Signature("Radix UI", "frontend", HTML, r"data-radix-|radix-:r", Confidence.MEDIUM),
    Signature("Spring Boot", "backend", HTML, r"Whitelabel Error Page", Confidence.HIGH),
    Signature("Supabase", "backend", HTML, r"supabase\.co|supabase-js|createClient\(", Confidence.HIGH),
    Signature("Firebase", "backend", HTML, r"firebaseapp\.com|firebaseio\.com|gstatic\.com/firebasejs",
              Confidence.HIGH),
    Signature("Clerk", "auth", HTML, r"clerk\.(?:com|dev|accounts)|@clerk/|clerk-js", Confidence.HIGH),
    Signature("Auth0", "auth", HTML, r"auth0\.com|auth0-spa-js|cdn\.auth0\.com", Confidence.HIGH),
    Signature("hCaptcha", "security", HTML, r"hcaptcha\.com|h-captcha", Confidence.HIGH),
    Signature("Sanity", "cms", HTML, r"sanity\.io|@sanity/|cdn\.sanity\.io", Confidence.HIGH),
    Signature("Ghost", "cms", HTML, r"ghost\.io|content/themes|__GHOST", Confidence.LOW),
    Signature("FastAPI", "backend", HTML, r"swagger-ui|/openapi\.json|redoc", Confidence.LOW),
    # --- v0.2 script-URL signatures ----------------------------------------
    Signature("Supabase", "backend", SCRIPT, r"@supabase/supabase-js", Confidence.HIGH),
    Signature("PocketBase", "backend", SCRIPT, r"pocketbase(?:[.-]([\d.]+))?", Confidence.MEDIUM, None, 1),
    Signature("Clerk", "auth", SCRIPT, r"@clerk/|clerk-js", Confidence.HIGH),
    Signature("Auth0", "auth", SCRIPT, r"auth0-spa-js|@auth0/", Confidence.HIGH),
    Signature("Payload CMS", "cms", SCRIPT, r"payloadcms|payload/dist", Confidence.MEDIUM),
    Signature("Axios", "frontend", SCRIPT, r"axios(?:[.-]([\d.]+))?(?:\.min)?\.js", Confidence.MEDIUM,
              None, 1),
    Signature("SvelteKit", "frontend", SCRIPT, r"@sveltejs/kit|/_app/immutable/", Confidence.HIGH),
)
