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
)
