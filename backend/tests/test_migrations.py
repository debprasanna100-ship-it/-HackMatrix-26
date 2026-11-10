"""Alembic migration tests (Task 2): upgrade/downgrade cycles on a temp DB.

SQLite is used as the migration target (batch ALTERs make the migrations
cross-dialect); production PostgreSQL runs the same scripts at startup via
app.storage.database.init_engine.
"""
from __future__ import annotations

from pathlib import Path

import pytest
from alembic import command
from alembic.config import Config
from sqlalchemy import create_engine, inspect, text

BACKEND_DIR = Path(__file__).resolve().parents[1]


def _alembic_config(db_url: str) -> Config:
    cfg = Config(str(BACKEND_DIR / "alembic.ini"))
    cfg.set_main_option("script_location", str(BACKEND_DIR / "alembic"))
    cfg.set_main_option("sqlalchemy.url", db_url)
    return cfg


def _tables(engine) -> set[str]:
    insp = inspect(engine)
    return {t for t in insp.get_table_names() if not t.startswith("sqlite_")}


def _columns(engine, table) -> set[str]:
    return {c["name"] for c in inspect(engine).get_columns(table)}


def test_upgrade_creates_full_schema(tmp_path, monkeypatch):
    db = tmp_path / "mig.db"
    monkeypatch.setenv("TRUSTLENS_DATABASE_URL", f"sqlite:///{db.as_posix()}")
    cfg = _alembic_config(f"sqlite:///{db.as_posix()}")

    command.upgrade(cfg, "head")

    engine = create_engine(f"sqlite:///{db.as_posix()}")
    tables = _tables(engine)
    assert {"reports", "users", "chain_commitments", "correlation_indicators",
            "alembic_version"} <= tables
    assert {"owner_id", "is_public"} <= _columns(engine, "reports")
    assert {"id", "email", "hashed_password", "role", "api_key_hash",
            "created_at", "updated_at", "email_verified"} <= _columns(engine, "users")
    engine.dispose()


def test_downgrade_reverses_auth_migration(tmp_path, monkeypatch):
    db = tmp_path / "mig2.db"
    monkeypatch.setenv("TRUSTLENS_DATABASE_URL", f"sqlite:///{db.as_posix()}")
    cfg = _alembic_config(f"sqlite:///{db.as_posix()}")

    command.upgrade(cfg, "head")
    command.downgrade(cfg, "0001_initial_schema")

    engine = create_engine(f"sqlite:///{db.as_posix()}")
    assert "users" not in _tables(engine)
    assert "owner_id" not in _columns(engine, "reports")
    assert "is_public" not in _columns(engine, "reports")
    # the baseline tables survive the auth downgrade
    assert {"reports", "chain_commitments", "correlation_indicators"} <= _tables(engine)
    engine.dispose()


def test_full_upgrade_downgrade_upgrade_cycle(tmp_path, monkeypatch):
    db = tmp_path / "mig3.db"
    url = f"sqlite:///{db.as_posix()}"
    monkeypatch.setenv("TRUSTLENS_DATABASE_URL", url)
    cfg = _alembic_config(url)

    command.upgrade(cfg, "head")
    command.downgrade(cfg, "base")
    engine = create_engine(url)
    assert _tables(engine).isdisjoint({"reports", "users", "chain_commitments",
                                       "correlation_indicators"})
    engine.dispose()

    command.upgrade(cfg, "head")
    engine = create_engine(url)
    assert {"reports", "users"} <= _tables(engine)
    engine.dispose()


def test_baseline_migration_is_reversible_from_scratch(tmp_path, monkeypatch):
    db = tmp_path / "mig4.db"
    monkeypatch.setenv("TRUSTLENS_DATABASE_URL", f"sqlite:///{db.as_posix()}")
    cfg = _alembic_config(f"sqlite:///{db.as_posix()}")

    command.upgrade(cfg, "0001_initial_schema")
    engine = create_engine(f"sqlite:///{db.as_posix()}")
    # the pre-auth baseline has no owner columns and no users table
    assert "users" not in _tables(engine)
    assert "owner_id" not in _columns(engine, "reports")
    engine.dispose()
    command.downgrade(cfg, "base")
    engine = create_engine(f"sqlite:///{db.as_posix()}")
    assert _tables(engine).isdisjoint({"reports", "chain_commitments",
                                       "correlation_indicators"})
    engine.dispose()


def test_alembic_models_match_orm_metadata(tmp_path, monkeypatch):
    """The head migration must produce a schema equivalent to the ORM models
    (the SQLite create_all path and the Alembic path must agree)."""
    db = tmp_path / "mig5.db"
    monkeypatch.setenv("TRUSTLENS_DATABASE_URL", f"sqlite:///{db.as_posix()}")
    cfg = _alembic_config(f"sqlite:///{db.as_posix()}")
    command.upgrade(cfg, "head")

    from app.storage.models import Base
    engine = create_engine(f"sqlite:///{db.as_posix()}")
    alembic_tables = {t: {c["name"] for c in inspect(engine).get_columns(t)}
                      for t in _tables(engine) if t != "alembic_version"}

    orm_engine = create_engine("sqlite://")
    Base.metadata.create_all(orm_engine)
    orm_tables = {t: {c["name"] for c in inspect(orm_engine).get_columns(t)}
                  for t in _tables(orm_engine)}
    orm_engine.dispose()
    engine.dispose()

    assert set(alembic_tables) == set(orm_tables)
    for table, cols in orm_tables.items():
        assert cols <= alembic_tables[table], f"{table}: {cols - alembic_tables[table]}"
