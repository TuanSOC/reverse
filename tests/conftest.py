"""Shared pytest fixtures."""

from __future__ import annotations

import sys
from collections.abc import Iterator
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parent))

from fixtures.mock_site import run_mock_site  # noqa: E402


@pytest.fixture
def mock_site() -> Iterator[str]:
    """Yield the base URL of a freshly started local mock site."""
    with run_mock_site() as base_url:
        yield base_url
