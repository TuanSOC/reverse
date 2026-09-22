"""Unit tests for the dom_security static heuristics."""

from __future__ import annotations

from webrecon.modules.dom_security.analysis import (
    find_dom_xss,
    find_prototype_pollution,
)


def test_dom_xss_source_to_sink_flagged() -> None:
    js = "var q = location.hash.slice(1); el.innerHTML = q;"
    hits = find_dom_xss(js)
    assert len(hits) == 1
    assert hits[0].kind == "dom_xss"
    assert "location.hash" in hits[0].detail
    assert "innerHTML" in hits[0].detail
    assert hits[0].snippet  # evidence snippet present


def test_dom_xss_document_write_referrer() -> None:
    js = "document.write(document.referrer);"
    hits = find_dom_xss(js)
    assert len(hits) == 1
    assert "referrer" in hits[0].detail


def test_dom_xss_no_source_not_flagged() -> None:
    # innerHTML assignment from a static constant is not attacker-controlled.
    js = "el.innerHTML = '<b>hello</b>';"
    assert find_dom_xss(js) == []


def test_dom_xss_source_without_sink_not_flagged() -> None:
    js = "var q = location.search; console.log(q);"
    assert find_dom_xss(js) == []


def test_dom_xss_dedups_repeated_pair() -> None:
    js = (
        "a.innerHTML = location.hash;\n"
        "b.innerHTML = location.hash;\n"
        "c.innerHTML = location.hash;"
    )
    hits = find_dom_xss(js)
    assert len(hits) == 1  # same source→sink pair collapses


def test_eval_with_location_flagged() -> None:
    js = "eval(location.hash.substring(1));"
    hits = find_dom_xss(js)
    assert len(hits) == 1
    assert "eval" in hits[0].detail


def test_prototype_pollution_unguarded_merge_flagged() -> None:
    js = "for (var k in src) { dst[k] = src[k]; }"
    hits = find_prototype_pollution(js)
    assert len(hits) == 1
    assert hits[0].kind == "prototype_pollution"
    assert hits[0].snippet


def test_prototype_pollution_guarded_merge_not_flagged() -> None:
    js = (
        "for (var k in src) {"
        " if (k === '__proto__') continue;"
        " dst[k] = src[k]; }"
    )
    assert find_prototype_pollution(js) == []


def test_prototype_pollution_plain_loop_not_flagged() -> None:
    # for-in with no bracket assignment is not a merge.
    js = "for (var k in obj) { total += obj[k].length; }"
    assert find_prototype_pollution(js) == []


def test_caps_bound_output() -> None:
    # Even with many sink occurrences, output stays within the cap.
    js = "".join(
        "el.insertAdjacentHTML('beforeend', location.search);\n" for _ in range(50)
    )
    assert len(find_dom_xss(js)) <= 10
