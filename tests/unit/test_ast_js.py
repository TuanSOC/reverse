"""Unit tests for the JS AST endpoint extractor bridge."""

from __future__ import annotations

import pytest

from webrecon.modules.javascript.ast_js import (
    _parse_output,
    extract_calls,
    node_available,
)


def test_parse_output_ok() -> None:
    raw = (b'{"ok":true,"calls":[{"kind":"fetch","method":"GET","url":"/a/{id}",'
           b'"line":2,"col":0,"confidence":0.8}]}')
    calls = _parse_output(raw)
    assert len(calls) == 1
    assert calls[0].kind == "fetch" and calls[0].method == "GET"
    assert calls[0].url == "/a/{id}" and calls[0].line == 2


def test_parse_output_failure_modes() -> None:
    assert _parse_output(b"") == []
    assert _parse_output(b"not json") == []
    assert _parse_output(b'{"ok":false,"error":"x"}') == []


@pytest.mark.skipif(not node_available(), reason="node/acorn not available")
async def test_extract_calls_live() -> None:
    js = (
        'fetch("/api/users/" + id);\n'
        'axios.get(`/api/orders/${orderId}`);\n'
        'api.request({url:"/v1/account", method:"POST"});\n'
        'var x=new XMLHttpRequest(); x.open("DELETE","/api/items/"+itemId);\n'
        'new WebSocket("wss://h/socket");\n'
    )
    calls = await extract_calls(js)
    by_url = {c.url: c for c in calls}
    assert by_url["/api/users/{id}"].method == "GET"
    assert by_url["/api/orders/{orderId}"].kind == "axios"
    assert by_url["/v1/account"].method == "POST"
    assert by_url["/api/items/{itemId}"].method == "DELETE"
    assert any(c.kind == "websocket" for c in calls)


async def test_extract_calls_empty_source() -> None:
    assert await extract_calls("") == []
