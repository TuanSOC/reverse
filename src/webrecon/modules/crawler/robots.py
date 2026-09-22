"""robots.txt parsing (§16).

Extracts Allow/Disallow groups and Sitemap declarations. We honor Disallow for
our own user-agent by default (polite crawling) but never treat "interesting"
disallowed paths as secret — they are surfaced for the operator, not auto-fetched
unless scope policy allows.
"""

from __future__ import annotations

from dataclasses import dataclass, field


@dataclass
class RobotsRules:
    disallow: list[str] = field(default_factory=list)
    allow: list[str] = field(default_factory=list)
    sitemaps: list[str] = field(default_factory=list)

    def is_disallowed(self, path: str) -> bool:
        """Longest-match Allow/Disallow decision (simplified robots semantics)."""
        best_dis = max((p for p in self.disallow if p and path.startswith(p)), key=len, default="")
        best_allow = max((p for p in self.allow if p and path.startswith(p)), key=len, default="")
        if not best_dis:
            return False
        return len(best_dis) > len(best_allow)


def parse_robots(text: str, *, user_agent: str = "*") -> RobotsRules:
    """Parse robots.txt, collecting rules for ``user_agent`` and ``*``."""
    rules = RobotsRules()
    # Track which agent-group the current lines apply to.
    current_agents: list[str] = []
    applicable = {user_agent.lower(), "*"}
    active = False

    for raw in text.splitlines():
        line = raw.split("#", 1)[0].strip()
        if not line or ":" not in line:
            continue
        key, _, value = line.partition(":")
        key = key.strip().lower()
        value = value.strip()

        if key == "user-agent":
            # A new group; consecutive user-agent lines share the next rules.
            current_agents = [value.lower()]
            active = any(a in applicable for a in current_agents)
        elif key == "disallow" and active:
            if value:
                rules.disallow.append(value)
        elif key == "allow" and active:
            if value:
                rules.allow.append(value)
        elif key == "sitemap":
            # Sitemap is global, independent of the active agent group.
            rules.sitemaps.append(value)
    return rules
