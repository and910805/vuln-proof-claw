"""Persist safe disposable Worker lifecycle metadata.

Revision ID: 0004_worker_executions
Revises: 0003_evidence_payloads
Create Date: 2026-08-01
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0004_worker_executions"
down_revision: str | None = "0003_evidence_payloads"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "worker_executions",
        sa.Column("id", sa.String(length=36), nullable=False),
        sa.Column("request_id", sa.String(length=255), nullable=False),
        sa.Column("engagement_id", sa.String(length=36), nullable=False),
        sa.Column("action_id", sa.String(length=36), nullable=False),
        sa.Column("runtime_identity", sa.String(length=500), nullable=False),
        sa.Column("state", sa.String(length=32), nullable=False),
        sa.Column("cleaned_up", sa.Boolean(), nullable=False),
        sa.Column("error_code", sa.String(length=255), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("version", sa.Integer(), nullable=False),
        sa.CheckConstraint(
            "state IN ('starting', 'running', 'completed', 'failed', "
            "'timed_out', 'cancelled', 'lost')",
            name="ck_worker_executions_state",
        ),
        sa.CheckConstraint(
            "NOT cleaned_up OR state IN "
            "('completed', 'failed', 'timed_out', 'cancelled', 'lost')",
            name="ck_worker_executions_cleanup_terminal",
        ),
        sa.ForeignKeyConstraint(
            ["action_id"],
            ["actions.id"],
            name="fk_worker_executions_action_id_actions",
            ondelete="CASCADE",
        ),
        sa.ForeignKeyConstraint(
            ["engagement_id"],
            ["engagements.id"],
            name="fk_worker_executions_engagement_id_engagements",
            ondelete="CASCADE",
        ),
        sa.PrimaryKeyConstraint("id", name="pk_worker_executions"),
        sa.UniqueConstraint("action_id", name="uq_worker_executions_action_id"),
        sa.UniqueConstraint("request_id", name="uq_worker_executions_request_id"),
    )
    op.create_index(
        "ix_worker_executions_action_id",
        "worker_executions",
        ["action_id"],
    )
    op.create_index(
        "ix_worker_executions_engagement_id",
        "worker_executions",
        ["engagement_id"],
    )
    op.create_index(
        "ix_worker_executions_state",
        "worker_executions",
        ["state"],
    )
    op.create_index(
        "ix_worker_executions_engagement_state",
        "worker_executions",
        ["engagement_id", "state"],
    )


def downgrade() -> None:
    op.drop_table("worker_executions")
