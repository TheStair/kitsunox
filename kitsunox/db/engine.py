"""Engine + session factory.

SQLite pragmas (WAL, foreign_keys) are applied on every connection so the live listener
and an ad-hoc query session can coexist without ``database is locked`` surprises.
"""

from __future__ import annotations

from collections.abc import Iterator
from contextlib import contextmanager

from sqlalchemy import Engine, create_engine, event
from sqlalchemy.orm import Session, sessionmaker

from kitsunox.config import Settings, get_settings

_engine: Engine | None = None
_Session: sessionmaker[Session] | None = None


def _configure_sqlite(dbapi_conn, _record) -> None:
    cur = dbapi_conn.cursor()
    cur.execute("PRAGMA journal_mode=WAL")
    cur.execute("PRAGMA foreign_keys=ON")
    cur.execute("PRAGMA busy_timeout=5000")
    cur.close()


def build_engine(settings: Settings | None = None) -> Engine:
    settings = settings or get_settings()
    settings.ensure_dirs()
    connect_args = {}
    if settings.db_url.startswith("sqlite"):
        connect_args["check_same_thread"] = False
    engine = create_engine(settings.db_url, future=True, connect_args=connect_args)
    if settings.db_url.startswith("sqlite"):
        event.listen(engine, "connect", _configure_sqlite)
    return engine


def get_engine() -> Engine:
    global _engine, _Session
    if _engine is None:
        _engine = build_engine()
        _Session = sessionmaker(bind=_engine, future=True, expire_on_commit=False)
    return _engine


def get_session_factory() -> sessionmaker[Session]:
    get_engine()
    assert _Session is not None
    return _Session


@contextmanager
def session_scope() -> Iterator[Session]:
    """Transactional scope: commit on success, roll back on error."""
    factory = get_session_factory()
    session = factory()
    try:
        yield session
        session.commit()
    except Exception:
        session.rollback()
        raise
    finally:
        session.close()
