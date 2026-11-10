"""SQLAlchemy engine/session management (SQLite by default, PostgreSQL-ready).

The ORM models live in storage/models.py; they are re-exported here so all
existing `from .database import ReportRow, ...` imports keep working.
"""
from __future__ import annotations

import logging
from pathlib import Path
from typing import Optional

from sqlalchemy import create_engine, inspect, text
from sqlalchemy.orm import sessionmaker

from ..config import Settings
from .models import (  # noqa: F401  (re-exported for backward compatibility)
    Base,
    ChainCommitmentRow,
    CorrelationIndicatorRow,
    ReportRow,
    UserRow,
)

logger = logging.getLogger("trustlens.storage")

# Columns added after the initial schema; SQLite cannot ALTER via create_all,
# so existing databases are upgraded in-place at startup (PostgreSQL users run
# real migrations — documented limitation of this MVP).
_SQLITE_ADDED_COLUMNS: dict[str, list[tuple[str, str]]] = {
    "reports": [
        ("owner_id", "VARCHAR(32)"),
        ("is_public", "BOOLEAN DEFAULT 0"),
    ],
}

_engine = None
_SessionLocal = None


def _ensure_sqlite_columns(engine) -> None:
    """Add post-launch columns to existing SQLite tables (idempotent)."""
    inspector = inspect(engine)
    with engine.begin() as conn:
        for table, columns in _SQLITE_ADDED_COLUMNS.items():
            if not inspector.has_table(table):
                continue
            existing = {col["name"] for col in inspector.get_columns(table)}
            for name, ddl in columns:
                if name not in existing:
                    conn.execute(text(f"ALTER TABLE {table} ADD COLUMN {name} {ddl}"))


def init_engine(settings: Settings) -> None:
    """Create the engine + schema (idempotent). SQLite needs a thread-affinity tweak.

    Schema-evolution policy:
      * PostgreSQL → Alembic migrations (`alembic upgrade head`) run at
        startup and FAIL CLOSED on error — a production schema must never
        drift silently.
      * SQLite (local dev/tests) → automatic `create_all` plus the in-place
        column fallback below; Alembic is not invoked (tests exercise the
        migrations explicitly against temporary databases).
    """
    global _engine, _SessionLocal
    if _engine is not None:
        return
    url = settings.database_url
    kwargs: dict = {"future": True, "echo": False}
    if url.startswith("sqlite"):
        kwargs["connect_args"] = {"check_same_thread": False}
    _engine = create_engine(url, **kwargs)
    _SessionLocal = sessionmaker(bind=_engine, expire_on_commit=False)
    if url.startswith("postgresql"):
        _run_alembic_migrations(settings)
    else:
        Base.metadata.create_all(_engine)
        if url.startswith("sqlite"):
            _ensure_sqlite_columns(_engine)


def _run_alembic_migrations(settings: Settings) -> None:
    """Apply Alembic migrations to the configured PostgreSQL database."""
    from alembic import command
    from alembic.config import Config as AlembicConfig

    alembic_dir = Path(__file__).resolve().parents[2] / "alembic"
    if not (alembic_dir / "env.py").exists():
        raise RuntimeError(
            "Alembic layout not found (backend/alembic); cannot migrate the "
            "PostgreSQL schema. Run `alembic upgrade head` manually."
        )
    cfg = AlembicConfig(str(alembic_dir.parent / "alembic.ini"))
    cfg.set_main_option("script_location", str(alembic_dir))
    cfg.set_main_option("sqlalchemy.url", settings.database_url)
    logger.info("running Alembic migrations for PostgreSQL database")
    command.upgrade(cfg, "head")


def engine():
    if _engine is None:
        raise RuntimeError("database engine not initialised; call init_engine() first")
    return _engine


def session():
    if _SessionLocal is None:
        raise RuntimeError("database session factory not initialised; call init_engine() first")
    return _SessionLocal()
