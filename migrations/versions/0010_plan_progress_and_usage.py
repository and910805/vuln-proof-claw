"""Record plan progress, cost over time, and control evidence.

Task progress makes an interrupted run resumable; usage samples put cost on a
timeline instead of a single total; the finding columns and the evidence role
let a differential verification be told from a bare observation.

Constraint names are bare tokens on purpose: the metadata naming convention
adds the ``ck_<table>_`` prefix, so passing a prefixed name here would produce
a doubly prefixed constraint that drifts from the models.

Revision ID: 0010_plan_progress_and_usage
Revises: 0009_engagement_l1_autonomy
Create Date: 2026-08-26
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0010_plan_progress_and_usage"
down_revision: str | None = "0009_engagement_l1_autonomy"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.add_column(
        "tasks",
        sa.Column("sequence", sa.Integer(), nullable=False, server_default="0"),
    )
    op.add_column(
        "tasks",
        sa.Column("state", sa.String(length=32), nullable=False, server_default="planned"),
    )
    op.add_column(
        "tasks",
        sa.Column("attempts", sa.Integer(), nullable=False, server_default="0"),
    )

    op.add_column("findings", sa.Column("cwe_id", sa.String(length=16), nullable=True))
    op.add_column(
        "findings",
        sa.Column(
            "verification_method",
            sa.String(length=32),
            nullable=False,
            server_default="observed",
        ),
    )

    op.add_column(
        "finding_evidence",
        sa.Column("role", sa.String(length=16), nullable=False, server_default="payload"),
    )

    op.create_table(
        "usage_samples",
        sa.Column("id", sa.String(length=36), nullable=False),
        sa.Column("engagement_id", sa.String(length=36), nullable=False),
        sa.Column("action_id", sa.String(length=36), nullable=True),
        sa.Column("kind", sa.String(length=32), nullable=False),
        sa.Column("recorded_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("quantity", sa.Integer(), nullable=False, server_default="1"),
        sa.Column("input_tokens", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("output_tokens", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("cost_micros", sa.BigInteger(), nullable=False, server_default="0"),
        sa.Column("wall_milliseconds", sa.BigInteger(), nullable=False, server_default="0"),
        sa.Column("engine", sa.String(length=64), nullable=False, server_default=""),
        sa.Column("model", sa.String(length=128), nullable=False, server_default=""),
        sa.CheckConstraint("quantity >= 0", name="quantity"),
        sa.CheckConstraint("input_tokens >= 0", name="input_tokens"),
        sa.CheckConstraint("output_tokens >= 0", name="output_tokens"),
        sa.CheckConstraint("cost_micros >= 0", name="cost_micros"),
        sa.CheckConstraint("wall_milliseconds >= 0", name="wall_milliseconds"),
        sa.ForeignKeyConstraint(["action_id"], ["actions.id"], ondelete="SET NULL"),
        sa.ForeignKeyConstraint(["engagement_id"], ["engagements.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index("ix_usage_samples_engagement_id", "usage_samples", ["engagement_id"])
    op.create_index("ix_usage_samples_kind", "usage_samples", ["kind"])
    op.create_index(
        "ix_usage_samples_engagement_recorded",
        "usage_samples",
        ["engagement_id", "recorded_at"],
    )


def downgrade() -> None:
    op.drop_index("ix_usage_samples_engagement_recorded", table_name="usage_samples")
    op.drop_index("ix_usage_samples_kind", table_name="usage_samples")
    op.drop_index("ix_usage_samples_engagement_id", table_name="usage_samples")
    op.drop_table("usage_samples")
    op.drop_column("finding_evidence", "role")
    op.drop_column("findings", "verification_method")
    op.drop_column("findings", "cwe_id")
    op.drop_column("tasks", "attempts")
    op.drop_column("tasks", "state")
    op.drop_column("tasks", "sequence")
