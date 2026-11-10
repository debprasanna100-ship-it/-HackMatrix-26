"""Alembic environment for TrustLens (sync SQLAlchemy models).

The database URL resolution order (see alembic.ini):
  1. TRUSTLENS_DATABASE_URL environment variable,
  2. sqlalchemy.url set programmatically on the Config (tests / init_engine),
  3. app.config Settings (backend/.env / defaults).
"""
from __future__ import annotations

import os
import sys
from logging.config import fileConfig
from pathlib import Path

from alembic import context
from sqlalchemy import engine_from_config, pool

# Make `app` importable when alembic is invoked from another cwd.
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from app.storage.models import Base  # noqa: E402

config = context.config

if config.config_file_name is not None:
    fileConfig(config.config_file_name)

target_metadata = Base.metadata


def _resolve_url() -> str:
    url = os.getenv("TRUSTLENS_DATABASE_URL") or config.get_main_option("sqlalchemy.url") or ""
    if not url:
        from app.config import get_settings
        url = get_settings().database_url
    return url


def run_migrations_offline() -> None:
    context.configure(
        url=_resolve_url(),
        target_metadata=target_metadata,
        literal_binds=True,
        dialect_opts={"paramstyle": "named"},
        render_as_batch=True,
    )
    with context.begin_transaction():
        context.run_migrations()


def run_migrations_online() -> None:
    from sqlalchemy import create_engine

    engine = create_engine(_resolve_url(), future=True)
    with engine.connect() as connection:
        context.configure(
            connection=connection,
            target_metadata=target_metadata,
            render_as_batch=True,  # batch ALTERs: required for SQLite evolution
        )
        with context.begin_transaction():
            context.run_migrations()
    engine.dispose()


if context.is_offline_mode():
    run_migrations_offline()
else:
    run_migrations_online()
