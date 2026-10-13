"""Rate-limit & protection-layer posture detection.

Passive by default (reads advertised rate-limit / WAF headers from responses the
scan already made — zero extra requests). An optional, hard-capped active probe
confirms whether a single endpoint enforces throttling; it runs only under the
``--active`` authorization gate and stays detection-only (no flooding, no bypass).
"""

from .module import RateLimitModule

__all__ = ["RateLimitModule"]
