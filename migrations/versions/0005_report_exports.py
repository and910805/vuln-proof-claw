"""Persist immutable engagement report exports.

Revision ID: 0005_report_exports
Revises: 0004_worker_executions
Create Date: 2026-08-01
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0005_report_exports"
down_revision: str | None = "0004_worker_executions"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "report_exports",
        sa.Column("id", sa.String(length=36), nullable=False),
        sa.Column("engagement_id", sa.String(length=36), nullable=False),
        sa.Column("format", sa.String(length=16), nullable=False),
        sa.Column("media_type", sa.String(length=255), nullable=False),
        sa.Column("digest", sa.String(length=64), nullable=False),
        sa.Column("size", sa.Integer(), nullable=False),
        sa.Column("idempotency_key", sa.String(length=255), nullable=False),
        sa.Column("content", sa.LargeBinary(), nullable=False),
        sa.Column("created_by", sa.String(length=320), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.CheckConstraint("format IN ('json', 'markdown')", name="format"),
        sa.CheckConstraint("size >= 0", name="size"),
        sa.ForeignKeyConstraint(
            ["engagement_id"], ["engagements.id"],
            name="fk_report_exports_engagement_id_engagements", ondelete="CASCADE"
        ),
        sa.PrimaryKeyConstraint("id", name="pk_report_exports"),
        sa.UniqueConstraint(
            "engagement_id", "idempotency_key",
            name="uq_report_exports_engagement_id_idempotency_key"
        ),
    )
    op.create_index("ix_report_exports_digest", "report_exports", ["digest"])
    op.create_index("ix_report_exports_engagement_id", "report_exports", ["engagement_id"])
    op.create_index(
        "ix_report_exports_engagement_created", "report_exports", ["engagement_id", "created_at"]
    )


def downgrade() -> None:
    op.drop_table("report_exports")
