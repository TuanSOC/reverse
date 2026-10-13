"""Synthesize an OpenAPI 3.1 specification from a scan's discovered endpoints.

Pure transformation (no I/O, no requests): it turns the endpoints and classified
parameters WebRecon already collected into a standards-compliant spec, so the
reconstructed API surface can be opened in Swagger UI, Postman, or a client
generator. Observation/provenance is preserved in ``x-webrecon`` extensions, and
nothing here contacts the target.
"""

from __future__ import annotations

from typing import Any
from urllib.parse import urlsplit

# Parameter classification -> (JSON Schema type, format or None).
_TYPE_BY_CLASS: dict[str, tuple[str, str | None]] = {
    "object_identifier": ("string", None),
    "user_identifier": ("string", None),
    "pagination": ("integer", None),
    "sorting": ("string", None),
    "token": ("string", None),
    "redirect": ("string", "uri"),
    "url": ("string", "uri"),
    "callback": ("string", "uri"),
    "file_path": ("string", None),
    "search": ("string", None),
    "filtering": ("string", None),
    "authentication": ("string", None),
    "unknown": ("string", None),
}
# Parameter source -> OpenAPI ``in`` location (json/form go in the request body).
_IN_BY_SOURCE = {"query": "query", "path": "path", "header": "header", "cookie": "cookie"}
_BODY_SOURCES = {"json", "form"}
_HTTP_METHODS = {"get", "put", "post", "delete", "options", "head", "patch", "trace"}


def _schema_for(classification: str, name: str) -> dict[str, Any]:
    typ, fmt = _TYPE_BY_CLASS.get(classification, ("string", None))
    low = name.lower()
    if typ == "string" and fmt is None:
        if "uuid" in low or "guid" in low:
            fmt = "uuid"
        elif low in ("email",) or low.endswith("_email"):
            fmt = "email"
        elif "date" in low or "time" in low:
            fmt = "date-time"
    schema: dict[str, Any] = {"type": typ}
    if fmt:
        schema["format"] = fmt
    return schema


def _path_template_params(path: str) -> list[str]:
    """Names inside ``{...}`` segments of a path template."""
    out = []
    for seg in path.split("/"):
        if seg.startswith("{") and seg.endswith("}") and len(seg) > 2:
            out.append(seg[1:-1])
    return out


def build_openapi(
    endpoints: list[dict],
    *,
    target_url: str | None,
    title: str | None = None,
    version: str = "1.0.0",
) -> dict[str, Any]:
    """Build an OpenAPI 3.1 document from endpoint rows (``queries.get_endpoints`` shape)."""
    base = urlsplit(target_url or "")
    host = base.hostname or "target"
    server = f"{base.scheme}://{base.netloc}" if base.scheme and base.netloc else None

    paths: dict[str, Any] = {}
    seen_ops: set[tuple[str, str]] = set()
    for e in endpoints:
        if (e.get("kind") or "rest") != "rest":
            continue  # graphql / websocket are not REST paths
        try:
            parts = urlsplit(e.get("url") or "")
        except ValueError:
            continue
        path = parts.path or "/"
        method = (e.get("method") or "get").lower()
        if method not in _HTTP_METHODS:
            method = "get"
        if (path, method) in seen_ops:
            continue
        seen_ops.add((path, method))

        meta = e.get("meta") or {}
        pmetas = meta.get("params") or []
        parameters: list[dict[str, Any]] = []
        body_props: dict[str, Any] = {}
        declared_path = set(_path_template_params(path))
        covered_path: set[str] = set()

        for pm in pmetas:
            name = pm.get("name")
            if not name:
                continue
            cls = pm.get("classification") or "unknown"
            src = pm.get("source") or "query"
            if src in _BODY_SOURCES:
                body_props[name] = _schema_for(cls, name)
                continue
            loc = _IN_BY_SOURCE.get(src, "query")
            if loc == "path":
                covered_path.add(name)
            parameters.append({
                "name": name, "in": loc, "required": loc == "path",
                "schema": _schema_for(cls, name),
                "description": cls.replace("_", " "),
            })
        # Ensure every {templated} path segment has a path parameter.
        for name in declared_path - covered_path:
            parameters.append({"name": name, "in": "path", "required": True,
                               "schema": {"type": "string"}, "description": "path identifier"})

        op: dict[str, Any] = {
            "summary": f"{method.upper()} {path}",
            "operationId": _operation_id(method, path),
            "responses": {"default": {"description": "Response (reconstructed; not verified)."}},
            "x-webrecon": {"observation": e.get("observation"),
                           "sources": meta.get("sources") or [],
                           "discovery_status": meta.get("discovery_status") or ""},
        }
        if parameters:
            op["parameters"] = parameters
        if body_props:
            op["requestBody"] = {"content": {"application/json": {"schema": {
                "type": "object", "properties": body_props}}}}
        seg = next((s for s in path.split("/") if s and not s.startswith("{")), None)
        if seg:
            op["tags"] = [seg]
        paths.setdefault(path, {})[method] = op

    doc: dict[str, Any] = {
        "openapi": "3.1.0",
        "info": {
            "title": title or f"{host} API (reconstructed)",
            "version": version,
            "description": (
                "Reconstructed by WebRecon from observed and referenced endpoints. "
                "Operations and parameter types are inferred, not confirmed against a "
                "live server; treat them as an attack-surface map, not a contract."),
        },
        "paths": paths,
    }
    if server:
        doc["servers"] = [{"url": server}]
    return doc


def _operation_id(method: str, path: str) -> str:
    slug = "".join(c if c.isalnum() else "_" for c in path).strip("_") or "root"
    slug = "_".join(filter(None, slug.split("_")))
    return f"{method}_{slug}"


def to_yaml(doc: dict[str, Any]) -> str:
    import yaml

    return yaml.safe_dump(doc, sort_keys=False, allow_unicode=True, default_flow_style=False)


async def openapi_from_db(db: Any, scan_id: str, *, title: str | None = None) -> dict[str, Any]:
    """Build the spec for a stored scan."""
    from ..api import queries

    overview = await queries.get_overview(db, scan_id)
    target = (overview or {}).get("target", {}).get("base_url") if overview else None
    endpoints = await queries.get_endpoints(db, scan_id)
    return build_openapi(endpoints, target_url=target, title=title)
