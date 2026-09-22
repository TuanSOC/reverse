"""Pure endpoint aggregation + classification (§19).

Consolidates endpoint candidates from three sources with strict provenance:

* **observed**  — the tool actually requested it and got a non-HTML (API-like)
  response (from the crawler).
* **referenced** — it appears as a link in HTML, a string in JavaScript, or a
  sitemap entry (we did not confirm it exists).
* **potential** — a looser fragment; existence unproven.

The aggregator never upgrades a weaker provenance to a stronger one: an endpoint
seen only in JavaScript stays ``referenced`` even if it *looks* real. Active
probing to turn ``referenced`` into ``observed`` is out of scope (browser mode,
P9, adds genuinely observed endpoints).
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field

from ...core.enums import Observation
from ...core.urls import normalize_url, parse_url

# Path segments that mark an "API-ish" URL.
_API_MARKERS = re.compile(
    r"/(?:api|v\d+|graphql|gql|rest|oauth2?|auth|internal|admin|webhooks?|"
    r"users?|accounts?|sessions?|tokens?)(?:/|$|\?)",
    re.IGNORECASE,
)

_SENSITIVE_MARKERS = re.compile(r"/(?:admin|internal|debug|graphql|actuator|_next/data)", re.I)

_OBS_RANK = {Observation.POTENTIAL: 0, Observation.REFERENCED: 1, Observation.OBSERVED: 2}


@dataclass
class Endpoint:
    url: str
    kind: str = "rest"  # rest | graphql | websocket
    observation: Observation = Observation.REFERENCED
    in_scope: bool = True
    sources: set[str] = field(default_factory=set)
    methods: set[str] = field(default_factory=set)
    # Observed query-param NAMES (values are dropped). The normalized `url` has
    # its query stripped, so we retain param names here for the apitest module.
    params: set[str] = field(default_factory=set)

    @property
    def sensitive(self) -> bool:
        return bool(_SENSITIVE_MARKERS.search(self.url))


def looks_like_api(url: str) -> bool:
    return bool(_API_MARKERS.search(url))


def _query_param_names(url: str) -> set[str]:
    from urllib.parse import parse_qsl, urlsplit

    try:
        query = urlsplit(url).query
    except ValueError:
        return set()
    return {k for k, _ in parse_qsl(query, keep_blank_values=True) if k}


def _kind(url: str) -> str:
    low = url.lower()
    if low.startswith(("ws://", "wss://")):
        return "websocket"
    if "graphql" in low or "/gql" in low:
        return "graphql"
    return "rest"


class EndpointAggregator:
    """Accumulates endpoint candidates and merges by normalized URL."""

    def __init__(self, base_host: str) -> None:
        self.base_host = base_host.lower()
        self._by_url: dict[str, Endpoint] = {}

    def add(
        self, url: str, observation: Observation, source: str, method: str | None = None
    ) -> None:
        url = url.strip()
        if not url:
            return
        key = self._key(url)
        if key is None:
            return
        in_scope = self._in_scope(url)
        ep = self._by_url.get(key)
        if ep is None:
            ep = Endpoint(url=key, kind=_kind(url), observation=observation, in_scope=in_scope)
            self._by_url[key] = ep
        # Keep the strongest provenance seen.
        if _OBS_RANK[observation] > _OBS_RANK[ep.observation]:
            ep.observation = observation
        ep.sources.add(source)
        if method:
            ep.methods.add(method.upper())
        # Retain observed query-param names before the query is normalized away.
        ep.params.update(_query_param_names(url))

    def _key(self, url: str) -> str | None:
        if url.lower().startswith(("ws://", "wss://")):
            return url
        try:
            return normalize_url(url, keep_query=False)
        except ValueError:
            return None

    def _in_scope(self, url: str) -> bool:
        try:
            if url.lower().startswith(("ws://", "wss://")):
                host = url.split("://", 1)[1].split("/", 1)[0].split(":")[0]
            else:
                host = parse_url(url).hostname
        except (ValueError, IndexError):
            return False
        host = host.lower()
        return host == self.base_host or host.endswith("." + self.base_host)

    def endpoints(self) -> list[Endpoint]:
        return sorted(
            self._by_url.values(),
            key=lambda e: (_OBS_RANK[e.observation], e.in_scope),
            reverse=True,
        )
