"""Add reusable, engagement-scoped approval presets.

Revision ID: 0008_approval_presets
Revises: 0007_sarif_exports
Create Date: 2026-08-03
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0008_approval_presets"
down_revision: str | None = "0007_sarif_exports"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "approval_presets",
        sa.Column("id", sa.String(length=36), nullable=False),
        sa.Column("engagement_id", sa.String(length=36), nullable=False),
        sa.Column("name", sa.String(length=255), nullable=False),
        sa.Column("action_types", sa.JSON(), nullable=False),
        sa.Column("target_prefixes", sa.JSON(), nullable=False),
        sa.Column("maximum_risk", sa.String(length=2), nullable=False),
        sa.Column("approval_ttl_seconds", sa.Integer(), nullable=False),
        sa.Column("enabled", sa.Boolean(), nullable=False),
        sa.Column("created_by", sa.String(length=320), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("version", sa.Integer(), nullable=False),
        sa.ForeignKeyConstraint(["engagement_id"], ["engagements.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("engagement_id", "name"),
    )
    op.create_index(
        "ix_approval_presets_engagement_enabled",
        "approval_presets",
        ["engagement_id", "enabled"],
        unique=False,
    )
    op.create_index(
        op.f("ix_approval_presets_engagement_id"),
        "approval_presets",
        ["engagement_id"],
        unique=False,
    )


def downgrade() -> None:
    op.drop_index(op.f("ix_approval_presets_engagement_id"), table_name="approval_presets")
    op.drop_index("ix_approval_presets_engagement_enabled", table_name="approval_presets")
    op.drop_table("approval_presets")
