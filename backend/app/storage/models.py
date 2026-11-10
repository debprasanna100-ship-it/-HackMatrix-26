"""SQLAlchemy ORM models (multi-tenant auth schema).

Moved from storage/database.py so the schema lives in a dedicated module;
database.py keeps the engine/session machinery and re-exports the models for
backward-compatible imports. Alembic migrations (backend/alembic) evolve
PostgreSQL deployments; SQLite local dev keeps the create_all + in-place
column fallback.

Multi-tenancy:
  * UserRow      — dashboard users (email + password) and programmatic users
                   (API keys, stored only as a SHA-256 hash).
  * ReportRow    — gained `owner_id` (the user who ran the analysis; NULL for
                   pre-auth/anonymous reports) and `is_public` (False by
                   default; when True any authenticated user can read it).
                   Owner/visibility live OUTSIDE the report JSON, so the
                   canonical integrity hash is unaffected by ownership.
"""
from __future__ import annotations

from datetime import datetime, timezone
from typing import Optional

from sqlalchemy import Boolean, DateTime, ForeignKey, String, Text, UniqueConstraint
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column


class Base(DeclarativeBase):
    pass


class ReportRow(Base):
    __tablename__ = "reports"

    id: Mapped[str] = mapped_column(String(32), primary_key=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), index=True
    )
    input_type: Mapped[str] = mapped_column(String(16), default="url")
    raw_input: Mapped[str] = mapped_column(Text)
    normalized_url: Mapped[Optional[str]] = mapped_column(String(2048), index=True)
    registrable_domain: Mapped[Optional[str]] = mapped_column(String(255), index=True)
    classification: Mapped[str] = mapped_column(String(32), default="inconclusive")
    report_json: Mapped[str] = mapped_column(Text)
    # --- multi-tenant access control (outside the hashed report content) ---
    owner_id: Mapped[Optional[str]] = mapped_column(
        String(32), ForeignKey("users.id"), index=True, default=None
    )
    is_public: Mapped[bool] = mapped_column(Boolean, default=False, index=True)


class UserRow(Base):
    __tablename__ = "users"

    id: Mapped[str] = mapped_column(String(32), primary_key=True)  # uuid4 hex
    email: Mapped[str] = mapped_column(String(255), unique=True, index=True)
    hashed_password: Mapped[str] = mapped_column(String(255))
    # SHA-256 of the API key — the raw key is shown exactly once at creation.
    api_key_hash: Mapped[Optional[str]] = mapped_column(String(64), unique=True, index=True)
    role: Mapped[str] = mapped_column(String(16), default="user")  # "user" | "admin"
    email_verified: Mapped[bool] = mapped_column(Boolean, default=False)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=lambda: datetime.now(timezone.utc)
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        onupdate=lambda: datetime.now(timezone.utc),
    )


class ChainCommitmentRow(Base):
    __tablename__ = "chain_commitments"

    report_id: Mapped[str] = mapped_column(String(32), primary_key=True)
    report_hash: Mapped[str] = mapped_column(String(66), index=True)  # 0x + 64 hex
    tx_hash: Mapped[str] = mapped_column(String(66))
    contract_address: Mapped[str] = mapped_column(String(42))
    chain_id: Mapped[int] = mapped_column()
    block_number: Mapped[int] = mapped_column()
    gas_used: Mapped[int] = mapped_column(default=0)
    committed_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=lambda: datetime.now(timezone.utc)
    )


class CorrelationIndicatorRow(Base):
    __tablename__ = "correlation_indicators"
    __table_args__ = (UniqueConstraint("kind", "value", "report_id", name="uq_indicator_report"),)

    id: Mapped[int] = mapped_column(primary_key=True, autoincrement=True)
    kind: Mapped[str] = mapped_column(String(16), index=True)   # domain | ip | issuer | message_hash
    value: Mapped[str] = mapped_column(String(255), index=True)
    report_id: Mapped[str] = mapped_column(String(32), index=True)
    classification: Mapped[str] = mapped_column(String(32))
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), index=True
    )
