"""Persist captured browser authentication sessions.

Revision ID: 0006_authentication_sessions
Revises: 0005_report_exports
Create Date: 2026-08-16
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0006_authentication_sessions"
down_revision: str | None = "0005_report_exports"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "authentication_sessions",
        sa.Column("id", sa.String(length=36), nullable=False),
        sa.Column("engagement_id", sa.String(length=36), nullable=False),
        sa.Column("label", sa.String(length=255), nullable=False),
        sa.Column("digest", sa.String(length=64), nullable=False),
        sa.Column("size", sa.Integer(), nullable=False),
        sa.Column("secret_key_names", sa.JSON(), nullable=False),
        sa.Column("material", sa.LargeBinary(), nullable=False),
        sa.Column("state", sa.String(length=32), nullable=False),
        sa.Column("created_by", sa.String(length=320), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("revoked_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("version", sa.Integer(), nullable=False),
        sa.CheckConstraint(
            "state IN ('active', 'revoked')",
            name="ck_authentication_sessions_state",
        ),
        sa.CheckConstraint("size >= 0", name="ck_authentication_sessions_size"),
        sa.ForeignKeyConstraint(
            ["engagement_id"],
            ["engagements.id"],
            name="fk_authentication_sessions_engagement_id_engagements",
            ondelete="CASCADE",
        ),
        sa.PrimaryKeyConstraint("id", name="pk_authentication_sessions"),
    )
    op.create_index(
        "ix_authentication_sessions_digest",
        "authentication_sessions",
        ["digest"],
    )
    op.create_index(
        "ix_authentication_sessions_engagement_id",
        "authentication_sessions",
        ["engagement_id"],
    )
    op.create_index(
        "ix_authentication_sessions_state",
        "authentication_sessions",
        ["state"],
    )
    op.create_index(
        "ix_authentication_sessions_engagement_state",
        "authentication_sessions",
        ["engagement_id", "state"],
    )


def downgrade() -> None:
    op.drop_table("authentication_sessions")
