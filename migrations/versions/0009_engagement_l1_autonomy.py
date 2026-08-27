"""Add explicit engagement-level L1 automatic execution policy.

Revision ID: 0009_engagement_l1_autonomy
Revises: 0008_approval_presets
Create Date: 2026-08-03
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0009_engagement_l1_autonomy"
down_revision: str | None = "0008_approval_presets"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.add_column(
        "engagements",
        sa.Column(
            "auto_execute_l1",
            sa.Boolean(),
            nullable=False,
            server_default=sa.false(),
        ),
    )


def downgrade() -> None:
    op.drop_column("engagements", "auto_execute_l1")
