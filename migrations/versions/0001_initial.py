"""Create the Phase 0 control-plane schema.

Revision ID: 0001_initial
Revises:
Create Date: 2026-07-30
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0001_initial"
down_revision: str | None = None
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

ID = sa.String(length=36)
DIGEST = sa.String(length=64)
TIMESTAMP = sa.DateTime(timezone=True)


def _identity(name: str) -> sa.Column[str]:
    return sa.Column(name, ID, nullable=False)


def _version() -> sa.Column[int]:
    return sa.Column("version", sa.Integer(), server_default="1", nullable=False)


def upgrade() -> None:
    op.create_table(
        "projects",
        _identity("id"),
        sa.Column("name", sa.String(length=255), nullable=False),
        sa.Column("created_at", TIMESTAMP, nullable=False),
        sa.PrimaryKeyConstraint("id", name="pk_projects"),
    )
    op.create_table(
        "engagements",
        _identity("id"),
        _identity("project_id"),
        sa.Column("name", sa.String(length=255), nullable=False),
        sa.Column("starts_at", TIMESTAMP, nullable=False),
        sa.Column("ends_at", TIMESTAMP, nullable=False),
        sa.Column("maximum_risk", sa.String(length=2), nullable=False),
        sa.Column("destructive_actions_enabled", sa.Boolean(), nullable=False),
        sa.Column("created_at", TIMESTAMP, nullable=False),
        _version(),
        sa.ForeignKeyConstraint(
            ["project_id"],
            ["projects.id"],
            name="fk_engagements_project_id_projects",
            ondelete="RESTRICT",
        ),
        sa.PrimaryKeyConstraint("id", name="pk_engagements"),
    )
    op.create_index("ix_engagements_project_id", "engagements", ["project_id"])
    op.create_index(
        "ix_engagements_project_created", "engagements", ["project_id", "created_at"]
    )
    op.create_table(
        "flows",
        _identity("id"),
        _identity("engagement_id"),
        sa.Column("objective", sa.Text(), nullable=False),
        sa.Column("created_at", TIMESTAMP, nullable=False),
        _version(),
        sa.ForeignKeyConstraint(
            ["engagement_id"],
            ["engagements.id"],
            name="fk_flows_engagement_id_engagements",
            ondelete="CASCADE",
        ),
        sa.PrimaryKeyConstraint("id", name="pk_flows"),
    )
    op.create_index("ix_flows_engagement_id", "flows", ["engagement_id"])
    op.create_index("ix_flows_engagement_created", "flows", ["engagement_id", "created_at"])
    op.create_table(
        "tasks",
        _identity("id"),
        _identity("flow_id"),
        sa.Column("title", sa.String(length=500), nullable=False),
        sa.Column("created_at", TIMESTAMP, nullable=False),
        sa.ForeignKeyConstraint(
            ["flow_id"],
            ["flows.id"],
            name="fk_tasks_flow_id_flows",
            ondelete="CASCADE",
        ),
        sa.PrimaryKeyConstraint("id", name="pk_tasks"),
    )
    op.create_index("ix_tasks_flow_id", "tasks", ["flow_id"])
    op.create_index("ix_tasks_flow_created", "tasks", ["flow_id", "created_at"])
    op.create_table(
        "approvals",
        _identity("id"),
        _identity("engagement_id"),
        sa.Column("action_type", sa.String(length=255), nullable=False),
        sa.Column("normalized_target", sa.Text(), nullable=False),
        sa.Column("parameter_digest", DIGEST, nullable=False),
        sa.Column("risk_level", sa.String(length=2), nullable=False),
        sa.Column("expires_at", TIMESTAMP, nullable=False),
        sa.Column("permitted_executions", sa.Integer(), nullable=False),
        sa.Column("approver", sa.String(length=320), nullable=False),
        sa.Column("approved_at", TIMESTAMP, nullable=False),
        sa.Column("consumed_executions", sa.Integer(), nullable=False),
        _version(),
        sa.ForeignKeyConstraint(
            ["engagement_id"],
            ["engagements.id"],
            name="fk_approvals_engagement_id_engagements",
            ondelete="CASCADE",
        ),
        sa.PrimaryKeyConstraint("id", name="pk_approvals"),
    )
    op.create_index("ix_approvals_engagement_id", "approvals", ["engagement_id"])
    op.create_index(
        "ix_approvals_engagement_expires", "approvals", ["engagement_id", "expires_at"]
    )
    op.create_table(
        "actions",
        _identity("id"),
        _identity("engagement_id"),
        _identity("task_id"),
        sa.Column("action_type", sa.String(length=255), nullable=False),
        sa.Column("normalized_target", sa.Text(), nullable=False),
        sa.Column("parameter_digest", DIGEST, nullable=False),
        sa.Column("risk_level", sa.String(length=2), nullable=False),
        sa.Column("idempotency_key", sa.String(length=255), nullable=False),
        sa.Column("state", sa.String(length=32), nullable=False),
        sa.Column("approval_id", ID, nullable=True),
        sa.Column("created_at", TIMESTAMP, nullable=False),
        sa.Column("started_at", TIMESTAMP, nullable=True),
        sa.Column("completed_at", TIMESTAMP, nullable=True),
        _version(),
        sa.ForeignKeyConstraint(
            ["approval_id"],
            ["approvals.id"],
            name="fk_actions_approval_id_approvals",
            ondelete="RESTRICT",
        ),
        sa.ForeignKeyConstraint(
            ["engagement_id"],
            ["engagements.id"],
            name="fk_actions_engagement_id_engagements",
            ondelete="CASCADE",
        ),
        sa.ForeignKeyConstraint(
            ["task_id"],
            ["tasks.id"],
            name="fk_actions_task_id_tasks",
            ondelete="CASCADE",
        ),
        sa.PrimaryKeyConstraint("id", name="pk_actions"),
        sa.UniqueConstraint(
            "engagement_id",
            "idempotency_key",
            name="uq_actions_engagement_id_idempotency_key",
        ),
    )
    op.create_index("ix_actions_engagement_id", "actions", ["engagement_id"])
    op.create_index("ix_actions_task_id", "actions", ["task_id"])
    op.create_index("ix_actions_state", "actions", ["state"])
    op.create_index("ix_actions_engagement_state", "actions", ["engagement_id", "state"])
    op.create_index("ix_actions_task_created", "actions", ["task_id", "created_at"])
    op.create_table(
        "evidence",
        _identity("id"),
        _identity("action_id"),
        sa.Column("tool_name", sa.String(length=255), nullable=False),
        sa.Column("tool_version", sa.String(length=128), nullable=False),
        sa.Column("digest", DIGEST, nullable=False),
        sa.Column("previous_digest", DIGEST, nullable=True),
        sa.Column("captured_at", TIMESTAMP, nullable=False),
        sa.ForeignKeyConstraint(
            ["action_id"],
            ["actions.id"],
            name="fk_evidence_action_id_actions",
            ondelete="CASCADE",
        ),
        sa.PrimaryKeyConstraint("id", name="pk_evidence"),
        sa.UniqueConstraint("action_id", "digest", name="uq_evidence_action_id_digest"),
    )
    op.create_index("ix_evidence_action_id", "evidence", ["action_id"])
    op.create_index("ix_evidence_digest", "evidence", ["digest"])
    op.create_index("ix_evidence_action_captured", "evidence", ["action_id", "captured_at"])
    op.create_table(
        "artifacts",
        _identity("id"),
        _identity("action_id"),
        sa.Column("kind", sa.String(length=32), nullable=False),
        sa.Column("media_type", sa.String(length=255), nullable=False),
        sa.Column("storage_reference", sa.Text(), nullable=False),
        sa.Column("digest", DIGEST, nullable=False),
        sa.Column("created_at", TIMESTAMP, nullable=False),
        sa.ForeignKeyConstraint(
            ["action_id"],
            ["actions.id"],
            name="fk_artifacts_action_id_actions",
            ondelete="CASCADE",
        ),
        sa.PrimaryKeyConstraint("id", name="pk_artifacts"),
    )
    op.create_index("ix_artifacts_action_id", "artifacts", ["action_id"])
    op.create_index("ix_artifacts_digest", "artifacts", ["digest"])
    op.create_table(
        "findings",
        _identity("id"),
        _identity("engagement_id"),
        sa.Column("title", sa.String(length=500), nullable=False),
        sa.Column("vulnerability_class", sa.String(length=255), nullable=False),
        sa.Column("affected_target", sa.Text(), nullable=False),
        sa.Column("status", sa.String(length=32), nullable=False),
        sa.Column("created_at", TIMESTAMP, nullable=False),
        _version(),
        sa.ForeignKeyConstraint(
            ["engagement_id"],
            ["engagements.id"],
            name="fk_findings_engagement_id_engagements",
            ondelete="CASCADE",
        ),
        sa.PrimaryKeyConstraint("id", name="pk_findings"),
    )
    op.create_index("ix_findings_engagement_id", "findings", ["engagement_id"])
    op.create_index("ix_findings_status", "findings", ["status"])
    op.create_index(
        "ix_findings_engagement_status", "findings", ["engagement_id", "status"]
    )
    op.create_table(
        "finding_evidence",
        _identity("finding_id"),
        _identity("evidence_id"),
        sa.ForeignKeyConstraint(
            ["evidence_id"],
            ["evidence.id"],
            name="fk_finding_evidence_evidence_id_evidence",
            ondelete="RESTRICT",
        ),
        sa.ForeignKeyConstraint(
            ["finding_id"],
            ["findings.id"],
            name="fk_finding_evidence_finding_id_findings",
            ondelete="CASCADE",
        ),
        sa.PrimaryKeyConstraint("finding_id", "evidence_id", name="pk_finding_evidence"),
    )
    op.create_table(
        "audit_events",
        _identity("id"),
        sa.Column("engagement_id", ID, nullable=True),
        sa.Column("event_type", sa.String(length=255), nullable=False),
        sa.Column("actor", sa.String(length=320), nullable=False),
        sa.Column("payload", sa.LargeBinary(), nullable=False),
        sa.Column("created_at", TIMESTAMP, nullable=False),
        sa.ForeignKeyConstraint(
            ["engagement_id"],
            ["engagements.id"],
            name="fk_audit_events_engagement_id_engagements",
            ondelete="SET NULL",
        ),
        sa.PrimaryKeyConstraint("id", name="pk_audit_events"),
    )
    op.create_index(
        "ix_audit_events_engagement_created", "audit_events", ["engagement_id", "created_at"]
    )


def downgrade() -> None:
    op.drop_table("audit_events")
    op.drop_table("finding_evidence")
    op.drop_table("findings")
    op.drop_table("artifacts")
    op.drop_table("evidence")
    op.drop_table("actions")
    op.drop_table("approvals")
    op.drop_table("tasks")
    op.drop_table("flows")
    op.drop_table("engagements")
    op.drop_table("projects")
