"""Pure detection helpers for the apitest module (no I/O)."""

from __future__ import annotations

import json
import re

from ..disclosure import mask_value
from ..javascript.patterns import SECRETS as _JS_SECRETS

# DB error signatures leaked in responses.
DB_ERROR = re.compile(
    r"(SQLSTATE\[|ORA-\d{5}|SQL syntax.*MySQL|You have an error in your SQL syntax"
    r"|PostgreSQL.*ERROR|PG::\w+Error|SQLite3?::|Microsoft OLE DB Provider for SQL Server"
    r"|Unclosed quotation mark after the character string"
    r"|System\.Data\.SqlClient\.SqlException|org\.hibernate\.|psycopg2\.|pymysql\.)",
    re.IGNORECASE,
)

# Response JSON keys that indicate sensitive data.
_SENSITIVE_KEY = re.compile(
    r"\"(password|passwd|pwd|secret|token|access_token|refresh_token|api[_-]?key"
    r"|apikey|ssn|authorization|private_key|client_secret)\"\s*:",
    re.IGNORECASE,
)

# Path segments that mark a privileged/sensitive endpoint.
SENSITIVE_PATH = re.compile(r"/(?:admin|internal|account|users?|me|private|secret)\b", re.I)

# Action-verb endpoints that may mutate state on GET — never probe these.
ACTION_VERB = re.compile(
    r"/(?:delete|remove|drop|destroy|reset|logout|signout|revoke|cancel|create|add"
    r"|update|edit|set|send|invite|purge|clear|disable|enable|deactivate|activate"
    r"|approve|reject|pay|charge|refund|write|upload|import|export|migrate)\b",
    re.I,
)


def has_db_error(body: str) -> bool:
    return bool(DB_ERROR.search(body))


def is_action_verb(url: str) -> bool:
    return bool(ACTION_VERB.search(url))


def is_sensitive_path(url: str) -> bool:
    return bool(SENSITIVE_PATH.search(url))


def looks_substantive_json(body: str, content_type: str | None) -> bool:
    """True if the body is a non-trivial JSON payload (array len >= 5 or object
    with >= 5 keys) — used to avoid flagging empty/login responses."""
    # An HTML response (e.g. a login/landing page) is never a substantive API
    # payload; bail early. Other/missing content-types still fall through to a
    # parse attempt, since some JSON APIs omit or mislabel the header.
    if content_type and "html" in content_type.lower():
        return False
    try:
        doc = json.loads(body)
    except (json.JSONDecodeError, ValueError):
        return False
    if isinstance(doc, list):
        return len(doc) >= 5
    if isinstance(doc, dict):
        return len(doc) >= 5
    return False


# Read-only GraphQL introspection query (sent via GET, url-encoded).
INTROSPECTION_QUERY = "{__schema{types{name}}}"


def is_introspection_result(body: str) -> bool:
    """True if a response is a GraphQL introspection result (data.__schema.types)."""
    try:
        doc = json.loads(body)
    except (json.JSONDecodeError, ValueError):
        return False
    schema = (doc.get("data") or {}).get("__schema") if isinstance(doc, dict) else None
    return isinstance(schema, dict) and "types" in schema


def find_sensitive_data(body: str) -> list[dict]:
    """Detect sensitive-looking data in a response body. Returns masked hits."""
    hits: list[dict] = []
    for key in {m.group(1).lower() for m in _SENSITIVE_KEY.finditer(body)}:
        hits.append({"kind": f"key:{key}", "sample": None})
    for kind, pat in _JS_SECRETS:
        m = pat.search(body)
        if m:
            hits.append({"kind": kind, "sample": mask_value(m.group(0))})
    return hits
