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
    assert "innerHTML" in hits[0].detail
    assert hits[0].snippet  # evidence snippet present
    assert hits[0].line == 1
    # via-variable taint flow: location.hash → var q → innerHTML
    assert "location.hash" in hits[0].flow and "innerHTML" in hits[0].flow


def test_dom_xss_reports_correct_line() -> None:
    js = "\n\nfunction f(){\n  var t = document.URL;\n  node.innerHTML = t;\n}"
    hits = find_dom_xss(js)
    assert len(hits) == 1
    assert hits[0].line == 5  # the sink line
    assert "document.URL" in hits[0].flow and "innerHTML" in hits[0].flow


def test_dom_xss_via_variable_far_apart() -> None:
    # Source and sink >160 chars apart → the 1-hop taint trace (not the window)
    # is what connects them: location.search → var u → innerHTML.
    js = "var u = location.search;\n" + ("var pad = 0;\n" * 30) + "box.innerHTML = u;"
    hits = find_dom_xss(js)
    assert hits
    assert "var u" in hits[0].flow  # names the tainting variable
    assert "location.search" in hits[0].flow and hits[0].line >= 30


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


def test_prototype_pollution_recursive_merge_flagged() -> None:
    # A genuine recursive deep-merge: isObject branch → nested merge call.
    js = (
        "function merge(dst, src){ for (var k in src) {"
        " if (isObject(src[k])) merge(dst[k], src[k]);"
        " else dst[k] = src[k]; } }"
    )
    hits = find_prototype_pollution(js)
    assert len(hits) == 1
    assert hits[0].kind == "prototype_pollution"
    assert hits[0].snippet


def test_prototype_pollution_nested_assign_flagged() -> None:
    js = "for (var k in src) { dst[k][sub] = src[k]; }"
    assert len(find_prototype_pollution(js)) == 1


def test_prototype_pollution_guarded_merge_not_flagged() -> None:
    js = (
        "for (var k in src) {"
        " if (k === '__proto__') continue;"
        " if (isObject(src[k])) merge(dst[k], src[k]); else dst[k] = src[k]; }"
    )
    assert find_prototype_pollution(js) == []


def test_prototype_pollution_shallow_copy_not_flagged() -> None:
    # A plain shallow copy is not exploitable → must NOT be flagged.
    js = "for (var k in src) { dst[k] = src[k]; }"
    assert find_prototype_pollution(js) == []


def test_prototype_pollution_react_prop_copy_not_flagged() -> None:
    # Real false-positive from stealx.fr: React's minified ref-excluding copy.
    js = "for(var s in r)s!==`ref`&&(o[s]=r[s])"
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
