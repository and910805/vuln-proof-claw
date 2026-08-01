"""Persist normalized engagement scope policies.

Revision ID: 0002_engagement_scopes
Revises: 0001_initial
Create Date: 2026-08-01
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0002_engagement_scopes"
down_revision: str | None = "0001_initial"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "engagement_scopes",
        sa.Column("engagement_id", sa.String(length=36), nullable=False),
        sa.Column("allowed_hostnames", sa.JSON(), nullable=False),
        sa.Column("allowed_cidrs", sa.JSON(), nullable=False),
        sa.Column("allowed_ports", sa.JSON(), nullable=False),
        sa.Column("allowed_schemes", sa.JSON(), nullable=False),
        sa.Column("allowed_paths", sa.JSON(), nullable=False),
        sa.Column("denied_hostnames", sa.JSON(), nullable=False),
        sa.Column("denied_cidrs", sa.JSON(), nullable=False),
        sa.Column("denied_paths", sa.JSON(), nullable=False),
        sa.Column("valid_from", sa.DateTime(timezone=True), nullable=True),
        sa.Column("valid_until", sa.DateTime(timezone=True), nullable=True),
        sa.ForeignKeyConstraint(
            ["engagement_id"],
            ["engagements.id"],
            name="fk_engagement_scopes_engagement_id_engagements",
            ondelete="CASCADE",
        ),
        sa.PrimaryKeyConstraint("engagement_id", name="pk_engagement_scopes"),
    )


def downgrade() -> None:
    op.drop_table("engagement_scopes")
