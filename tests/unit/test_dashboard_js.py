"""Guard: the dashboard's inline JavaScript must be syntactically valid.

A single JS syntax error in the self-contained dashboard breaks the *entire*
page (blank screen), and Python tests don't otherwise execute it. This test
extracts the inline module script and validates it with `node --check` when
Node is available (skipped otherwise, e.g. minimal CI without Node).
"""

from __future__ import annotations

import re
import shutil
import subprocess
from pathlib import Path

import pytest

_INDEX = (
    Path(__file__).resolve().parents[2]
    / "src" / "webrecon" / "api" / "static" / "index.html"
)


def _extract_script() -> str:
    html = _INDEX.read_text(encoding="utf-8")
    m = re.search(r'<script type="module">(.*)</script>', html, re.S)
    assert m, "dashboard is missing its <script type=module> block"
    return m.group(1)


def test_dashboard_has_script() -> None:
    assert len(_extract_script()) > 1000  # sanity: the app is present


@pytest.mark.skipif(shutil.which("node") is None, reason="node not available")
def test_dashboard_js_is_valid_syntax(tmp_path) -> None:
    js = tmp_path / "app.mjs"
    js.write_text(_extract_script(), encoding="utf-8")
    result = subprocess.run(  # noqa: S603
        [shutil.which("node"), "--check", str(js)],
        capture_output=True,
        text=True,
    )
    assert result.returncode == 0, f"dashboard JS has a syntax error:\n{result.stderr}"
