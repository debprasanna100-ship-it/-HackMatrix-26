"""Baseline schema: reports, chain_commitments, correlation_indicators.

Revision ID: 0001_initial_schema
Revises:
Create Date: 2026-11-09
"""
from __future__ import annotations

from alembic import op
import sqlalchemy as sa

revision = "0001_initial_schema"
down_revision = None
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "reports",
        sa.Column("id", sa.String(32), primary_key=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, index=True),
        sa.Column("input_type", sa.String(16), server_default="url"),
        sa.Column("raw_input", sa.Text(), nullable=False),
        sa.Column("normalized_url", sa.String(2048), index=True),
        sa.Column("registrable_domain", sa.String(255), index=True),
        sa.Column("classification", sa.String(32), server_default="inconclusive"),
        sa.Column("report_json", sa.Text(), nullable=False),
    )
    op.create_table(
        "chain_commitments",
        sa.Column("report_id", sa.String(32), primary_key=True),
        sa.Column("report_hash", sa.String(66), index=True),
        sa.Column("tx_hash", sa.String(66)),
        sa.Column("contract_address", sa.String(42)),
        sa.Column("chain_id", sa.Integer()),
        sa.Column("block_number", sa.Integer()),
        sa.Column("gas_used", sa.Integer()),
        sa.Column("committed_at", sa.DateTime(timezone=True)),
    )
    op.create_table(
        "correlation_indicators",
        sa.Column("id", sa.Integer(), primary_key=True, autoincrement=True),
        sa.Column("kind", sa.String(16), index=True),
        sa.Column("value", sa.String(255), index=True),
        sa.Column("report_id", sa.String(32), index=True),
        sa.Column("classification", sa.String(32)),
        sa.Column("created_at", sa.DateTime(timezone=True), index=True),
        sa.UniqueConstraint("kind", "value", "report_id", name="uq_indicator_report"),
    )


def downgrade() -> None:
    op.drop_table("correlation_indicators")
    op.drop_table("chain_commitments")
    op.drop_table("reports")
