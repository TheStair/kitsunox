"""Alembic environment.

The DB URL comes from Kitsunox settings (``KITSUNOX_DB_URL`` / ``.env``), not from
``alembic.ini`` — keep one source of truth.
"""

from logging.config import fileConfig

from alembic import context

from kitsunox.config import get_settings
from kitsunox.db.engine import build_engine
from kitsunox.db.models import Base

config = context.config

if config.config_file_name is not None:
    fileConfig(config.config_file_name)

target_metadata = Base.metadata


def run_migrations_offline() -> None:
    context.configure(
        url=get_settings().db_url,
        target_metadata=target_metadata,
        literal_binds=True,
        dialect_opts={"paramstyle": "named"},
        render_as_batch=True,
    )
    with context.begin_transaction():
        context.run_migrations()


def run_migrations_online() -> None:
    connectable = build_engine()
    with connectable.connect() as connection:
        context.configure(
            connection=connection,
            target_metadata=target_metadata,
            # batch mode: required for ALTER TABLE on SQLite
            render_as_batch=True,
        )
        with context.begin_transaction():
            context.run_migrations()
    connectable.dispose()


if context.is_offline_mode():
    run_migrations_offline()
else:
    run_migrations_online()
