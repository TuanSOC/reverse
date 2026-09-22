"""Compiled regex patterns for static JS analysis (§8).

Deliberately conservative. Anything matched here is a *string observed in the
JavaScript* — never proof that an endpoint exists. The module classifies these
as ``referenced`` (an explicit path/URL in the code) or ``potential`` (a looser
fragment), never ``observed``.
"""

from __future__ import annotations

import re

# API-ish absolute paths referenced as string literals.
API_PATH = re.compile(
    r"""["'`](/(?:api|v\d+|graphql|gql|rest|auth|oauth2?|internal|admin|users?|"""
    r"""accounts?|sessions?|tokens?|webhooks?)(?:/[A-Za-z0-9_\-./{}:]*)?)["'`]"""
)

# Absolute http(s) URLs.
ABSOLUTE_URL = re.compile(r"""https?://[A-Za-z0-9._~%\-]+(?:/[A-Za-z0-9._~%\-/{}]*)?""")

# WebSocket URLs.
WEBSOCKET = re.compile(r"""wss?://[A-Za-z0-9._~%\-]+(?:/[A-Za-z0-9._~%\-/{}]*)?""")

# GraphQL indicators.
GRAPHQL = re.compile(r"""(/graphql\b|__typename|gql`|graphql\()""")

# Source map reference.
SOURCEMAP = re.compile(r"""//[#@]\s*sourceMappingURL=([^\s'"]+)""")

# Analytics IDs.
ANALYTICS = re.compile(r"""\b(UA-\d{4,}-\d+|G-[A-Z0-9]{6,}|GTM-[A-Z0-9]{4,}|AW-\d{6,})\b""")

# Cloud service references.
CLOUD = re.compile(
    r"""([a-z0-9.\-]+\.s3(?:[.\-][a-z0-9\-]+)?\.amazonaws\.com"""
    r"""|s3://[a-z0-9.\-]+"""
    r"""|[a-z0-9\-]+\.firebaseio\.com"""
    r"""|[a-z0-9\-]+\.cloudfront\.net"""
    r"""|storage\.googleapis\.com/[a-z0-9._\-]+"""
    r"""|[a-z0-9\-]+\.blob\.core\.windows\.net)""",
    re.IGNORECASE,
)

# High-signal secret patterns (matches are MASKED before storage — §35/§14).
SECRETS: tuple[tuple[str, re.Pattern[str]], ...] = (
    ("aws_access_key_id", re.compile(r"\bAKIA[0-9A-Z]{16}\b")),
    ("google_api_key", re.compile(r"\bAIza[0-9A-Za-z_\-]{35}\b")),
    ("slack_token", re.compile(r"\bxox[baprs]-[0-9A-Za-z\-]{10,}\b")),
    ("github_pat", re.compile(r"\bghp_[0-9A-Za-z]{36}\b")),
    ("private_key", re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH |)PRIVATE KEY-----")),
    ("stripe_live_key", re.compile(r"\bsk_live_[0-9A-Za-z]{16,}\b")),
    ("jwt", re.compile(r"\beyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\b")),
)

# Framework/library clues (name -> pattern) for corroboration.
FRAMEWORK_CLUES: tuple[tuple[str, re.Pattern[str]], ...] = (
    ("webpack", re.compile(r"webpackJsonp|__webpack_require__")),
    ("React", re.compile(
        r"react(?:-dom)?(?:\.production|\.development)?\.min\.js|React\.createElement"
    )),
    ("Angular", re.compile(r"@angular/|ng\.probe|platformBrowser")),
    ("Vue.js", re.compile(r"Vue\.config|__vue__|vue\.runtime")),
    ("Next.js", re.compile(r"__NEXT_DATA__|/_next/")),
    ("Sentry", re.compile(r"sentry(?:-cdn)?\.io|Sentry\.init")),
)
