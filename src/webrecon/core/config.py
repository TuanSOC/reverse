"""Configuration models.

All knobs live here as validated pydantic models so the CLI, API, and tests
share one definition. Defaults are deliberately conservative (§34): low
concurrency, a request delay, private targets disabled.
"""

from __future__ import annotations

from enum import Enum

from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict

DEFAULT_USER_AGENT = "WebRecon/0.1 (+authorized-assessment)"


class ScopeMode(str, Enum):
    """How broadly the crawler/engine may roam relative to the target (§4)."""

    SAME_ORIGIN = "same-origin"  # scheme+host+port must match
    SAME_DOMAIN = "same-domain"  # same registrable host, any port/scheme
    INCLUDE_SUBDOMAINS = "include-subdomains"  # host or any subdomain


class ScopeConfig(BaseSettings):
    """Boundary the engine must respect on every request (§4)."""

    model_config = SettingsConfigDict(extra="forbid")

    mode: ScopeMode = ScopeMode.SAME_DOMAIN
    allowed_hosts: list[str] = Field(default_factory=list)
    disallowed_hosts: list[str] = Field(default_factory=list)
    include_paths: list[str] = Field(default_factory=list)
    exclude_paths: list[str] = Field(default_factory=list)
    max_depth: int = 3
    max_pages: int = 300
    max_requests: int = 2000
    # Lab/local testing must be explicitly enabled (§3). When False the SSRF
    # guard blocks all private/loopback/link-local/metadata targets.
    allow_private_targets: bool = False


class RateLimitConfig(BaseSettings):
    """Conservative-by-default politeness controls (§34)."""

    model_config = SettingsConfigDict(extra="forbid")

    requests_per_second: float = 3.0
    concurrency: int = 5
    per_host_concurrency: int = 3
    request_delay_seconds: float = 0.0
    max_retries: int = 2
    backoff_base_seconds: float = 0.5
    respect_429: bool = True


class HttpConfig(BaseSettings):
    """Shared HTTP engine settings (§5)."""

    model_config = SettingsConfigDict(extra="forbid")

    timeout_seconds: float = 20.0
    max_response_bytes: int = 10 * 1024 * 1024  # 10 MiB hard cap (§35)
    max_redirects: int = 10
    follow_redirects: bool = True
    user_agent: str = DEFAULT_USER_AGENT
    verify_tls: bool = True


class CrawlConfig(BaseSettings):
    """Crawler behavior knobs (§7)."""

    model_config = SettingsConfigDict(extra="forbid")

    # Politely honor robots.txt disallow rules by default (§16).
    respect_robots: bool = True
    # Record referenced sub-resources (scripts/styles/images) without fetching
    # their bodies during the crawl; later modules decide what to download.
    record_assets: bool = True
    # Cap on distinct assets recorded, to bound memory on large sites.
    max_assets: int = 5000
    # Treat URLs that differ only by query string as distinct pages.
    distinct_query: bool = True
    # Also parse sitemap.xml and compare against crawled URLs (§17).
    parse_sitemap: bool = True


class JsConfig(BaseSettings):
    """JavaScript-analysis knobs (§8/§9)."""

    model_config = SettingsConfigDict(extra="forbid")

    # Cap how many in-scope JS files to download and analyze.
    max_files: int = 50
    # Follow sourceMappingURL and probe <script>.map for exposed source maps.
    fetch_source_maps: bool = True
    # Scan JS bodies for high-signal secret patterns (matches are masked).
    scan_secrets: bool = True


class BrowserConfig(BaseSettings):
    """Headless-browser (Playwright) options (§20)."""

    model_config = SettingsConfigDict(extra="forbid")

    # Capture a full-page screenshot of the rendered target.
    screenshots: bool = True
    # Where to write screenshots (created on demand); None = skip saving.
    screenshot_dir: str | None = "scans/screenshots"
    nav_timeout_ms: int = 15000
    wait_until: str = "networkidle"  # load | domcontentloaded | networkidle


class ScanConfig(BaseSettings):
    """Top-level scan configuration assembled from the sub-configs."""

    model_config = SettingsConfigDict(extra="forbid", env_prefix="WEBRECON_")

    scope: ScopeConfig = Field(default_factory=ScopeConfig)
    rate: RateLimitConfig = Field(default_factory=RateLimitConfig)
    http: HttpConfig = Field(default_factory=HttpConfig)
    crawl: CrawlConfig = Field(default_factory=CrawlConfig)
    js: JsConfig = Field(default_factory=JsConfig)
    browser: BrowserConfig = Field(default_factory=BrowserConfig)
    # Enabled modules; empty means "all registered modules".
    enabled_modules: list[str] = Field(default_factory=list)
    browser_mode: bool = False
    database_url: str = "sqlite+aiosqlite:///webrecon.db"
    log_level: str = "INFO"
