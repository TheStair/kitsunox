"""Shared fixtures.

Every test gets an isolated temp ``data/`` dir and a fresh SQLite schema. External HTTP
is never hit unless a test is explicitly marked ``network``.
"""

from __future__ import annotations

from collections.abc import Iterator

import pytest


@pytest.fixture
def settings(tmp_path, monkeypatch):
    monkeypatch.setenv("KITSUNOX_DATA_DIR", str(tmp_path / "data"))
    monkeypatch.setenv("KITSUNOX_DB_URL", f"sqlite:///{tmp_path / 'data' / 'kitsunox.db'}")
    monkeypatch.setenv("KITSUNOX_FEED_START", "0")

    import kitsunox.config as config
    import kitsunox.db.engine as engine

    config.get_settings.cache_clear()
    # reset cached engine/session between tests
    engine._engine = None
    engine._Session = None

    s = config.get_settings()
    s.ensure_dirs()
    yield s

    config.get_settings.cache_clear()
    engine._engine = None
    engine._Session = None


@pytest.fixture
def db(settings) -> Iterator[None]:
    from kitsunox.db.engine import get_engine
    from kitsunox.db.models import Base

    Base.metadata.create_all(get_engine())
    yield
    Base.metadata.drop_all(get_engine())


@pytest.fixture
def repo(db):
    from kitsunox.db.engine import session_scope
    from kitsunox.db.repo import Repository

    with session_scope() as session:
        yield Repository(session)


@pytest.fixture
def make_tgz():
    """Factory: path->bytes mapping -> npm-style .tgz bytes."""
    from kitsunox.analysis.tarball import make_tarball_bytes

    return make_tarball_bytes
