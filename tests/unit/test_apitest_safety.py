"""apitest safety invariants: worklist filtering + budget (unit)."""

from __future__ import annotations

from webrecon.core.enums import Observation
from webrecon.modules.api.classify import Endpoint
from webrecon.modules.apitest.module import MAX_REQUESTS, ApiTestModule


def _ep(url, obs=Observation.OBSERVED, kind="rest", in_scope=True) -> Endpoint:
    return Endpoint(url=url, kind=kind, observation=obs, in_scope=in_scope)


def test_worklist_only_observed_inscope_rest_nonverb() -> None:
    mod = ApiTestModule()
    eps = [
        _ep("https://x/api/users"),                                  # keep
        _ep("https://x/api/delete?id=1"),                            # verb -> skip
        _ep("https://x/api/guessed", obs=Observation.REFERENCED),    # referenced -> skip
        _ep("https://x/api/x", in_scope=False),                      # out of scope -> skip
        _ep("wss://x/socket", kind="websocket"),                     # non-rest -> skip
        _ep("https://x/api/orders"),                                 # keep
    ]
    urls = {e.url for e in mod._worklist(eps)}
    assert urls == {"https://x/api/users", "https://x/api/orders"}


def test_budget_constant_is_bounded() -> None:
    assert MAX_REQUESTS == 200
