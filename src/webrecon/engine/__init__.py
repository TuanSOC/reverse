"""Network engine: SSRF guard, scope engine, rate limiter, shared HTTP engine.

All network access flows through :class:`HttpEngine`, which enforces the SSRF
guard on every hop, the scope gate, response-size caps, and rate limiting.
"""

from .http_engine import HttpEngine, HttpEngineError, HttpResponse, RedirectHop
from .rate_limiter import RateLimiter
from .scope_engine import ScopeDecision, ScopeEngine
from .ssrf_guard import SsrfGuard

__all__ = [
    "HttpEngine",
    "HttpEngineError",
    "HttpResponse",
    "RedirectHop",
    "RateLimiter",
    "ScopeDecision",
    "ScopeEngine",
    "SsrfGuard",
]
