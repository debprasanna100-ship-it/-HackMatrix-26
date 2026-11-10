"""Multi-tenant auth: users table + reports ownership columns.

Revision ID: 0002_multi_tenant_auth
Revises: 0001_initial_schema
Create Date: 2026-11-09
"""
from __future__ import annotations

from alembic import op
import sqlalchemy as sa

revision = "0002_multi_tenant_auth"
down_revision = "0001_initial_schema"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "users",
        sa.Column("id", sa.String(32), primary_key=True),
        sa.Column("email", sa.String(255), nullable=False, unique=True, index=True),
        sa.Column("hashed_password", sa.String(255), nullable=False),
        sa.Column("api_key_hash", sa.String(64), unique=True, index=True),
        sa.Column("role", sa.String(16), server_default="user"),
        sa.Column("email_verified", sa.Boolean(), server_default=sa.false()),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
    )
    with op.batch_alter_table("reports") as batch:
        batch.add_column(sa.Column("owner_id", sa.String(32), nullable=True))
        batch.add_column(sa.Column("is_public", sa.Boolean(), server_default=sa.false()))
        batch.create_index("ix_reports_owner_id", ["owner_id"])
        batch.create_index("ix_reports_is_public", ["is_public"])
        # SQLite cannot add a FOREIGN KEY via ALTER; batch mode recreates the
        # table with the constraint. PostgreSQL applies it directly.
        batch.create_foreign_key(
            "fk_reports_owner_id_users", "users", ["owner_id"], ["id"]
        )


def downgrade() -> None:
    with op.batch_alter_table("reports") as batch:
        batch.drop_constraint("fk_reports_owner_id_users", type_="foreignkey")
        batch.drop_index("ix_reports_is_public")
        batch.drop_index("ix_reports_owner_id")
        batch.drop_column("is_public")
        batch.drop_column("owner_id")
    op.drop_table("users")
