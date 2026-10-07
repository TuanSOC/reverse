"""Unit tests for parameter-intelligence classification (pure)."""

from __future__ import annotations

from webrecon.modules.api.params import (
    AUTH,
    OBJECT_ID,
    PAGINATION,
    REDIRECT,
    SEARCH,
    SORTING,
    TOKEN,
    UNKNOWN,
    USER_ID,
    classify_param,
    classify_params,
)


def test_object_identifier() -> None:
    assert classify_param("id").classification == OBJECT_ID
    assert classify_param("order_id").classification == OBJECT_ID
    assert classify_param("productId").classification == OBJECT_ID


def test_user_identifier() -> None:
    assert classify_param("user_id").classification == USER_ID
    assert classify_param("email").classification == USER_ID


def test_redirect_and_token() -> None:
    assert classify_param("redirect_uri").classification == REDIRECT
    assert classify_param("next").classification == REDIRECT
    assert classify_param("access_token").classification == TOKEN
    assert classify_param("csrf").classification == TOKEN


def test_pagination_sorting_search() -> None:
    assert classify_param("page").classification == PAGINATION
    assert classify_param("limit").classification == PAGINATION
    assert classify_param("sort_by").classification == SORTING
    assert classify_param("q").classification == SEARCH


def test_auth_param() -> None:
    assert classify_param("password").classification == AUTH
    assert classify_param("otp").classification == AUTH


def test_value_shape_fallback() -> None:
    # uninformative name, but JWT value → token
    jwt = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.abc"
    assert classify_param("x", jwt).classification == TOKEN
    # uuid value → object id
    assert classify_param("x", "550e8400-e29b-41d4-a716-446655440000").classification == OBJECT_ID


def test_unknown() -> None:
    assert classify_param("wibble").classification == UNKNOWN


def test_classify_params_dedup_and_confidence() -> None:
    out = classify_params(["id", "id", "redirect"])
    assert [p.name for p in out] == ["id", "redirect"]
    assert all(0.0 <= p.confidence <= 1.0 for p in out)
