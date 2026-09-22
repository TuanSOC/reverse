"""Scanner modules.

Importing this package registers all built-in modules onto
``core.registry.default_registry`` (each module module calls
``@default_registry.register``). New modules are added to this import list as
their phases land.
"""

from . import (  # noqa: F401  (import side-effect: registration)
    api,
    apitest,
    browser,
    cookies,
    cors,
    crawler,
    dns,
    dom_security,
    exposure,
    forms_auth,
    headers,
    http,
    ip_intel,
    javascript,
    scope,
    security,
    subdomains,
    target,
    technology,
    tls,
)

__all__ = [
    "target",
    "scope",
    "http",
    "crawler",
    "dns",
    "tls",
    "headers",
    "cookies",
    "cors",
    "technology",
    "javascript",
    "browser",
    "exposure",
    "subdomains",
    "ip_intel",
    "dom_security",
    "forms_auth",
    "api",
    "apitest",
    "security",
]
