"""Shared test fixtures.

Every `fetch` test gets its on-disk cache redirected to a per-test tmp dir, so tests
never read or write the real `.cache/gh/` and never leak state between runs.
"""

from __future__ import annotations

import pytest

from kitsunox import fetch


@pytest.fixture(autouse=True)
def isolated_cache(tmp_path, monkeypatch):
    monkeypatch.setattr(fetch, "CACHE_DIR", tmp_path / "cache")
