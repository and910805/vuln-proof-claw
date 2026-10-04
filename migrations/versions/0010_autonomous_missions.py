"""Add persistent autonomous mission, lead, and knowledge-base tables.

Revision ID: 0010_autonomous_missions
Revises: 0009_engagement_l1_autonomy
Create Date: 2026-10-04
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0010_autonomous_missions"
down_revision: str | None = "0009_engagement_l1_autonomy"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:  # noqa: PLR0915 - one migration per coherent schema change
    op.add_column(
        "engagement_scopes",
        sa.Column("allowed_wildcards", sa.JSON(), nullable=False, server_default="[]"),
    )
    op.add_column(
        "engagement_scopes",
        sa.Column("denied_wildcards", sa.JSON(), nullable=False, server_default="[]"),
    )

    op.create_table(
        "missions",
        sa.Column("id", sa.String(length=36), nullable=False),
        sa.Column("engagement_id", sa.String(length=36), nullable=False),
        sa.Column("name", sa.String(length=255), nullable=False),
        sa.Column("state", sa.String(length=32), nullable=False),
        sa.Column("maximum_autonomous_risk", sa.String(length=2), nullable=False),
        sa.Column("kill_switch_engaged", sa.Boolean(), nullable=False),
        sa.Column("cadence", sa.JSON(), nullable=False),
        sa.Column("budget", sa.JSON(), nullable=False),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("version", sa.Integer(), nullable=False),
        sa.CheckConstraint(
            "maximum_autonomous_risk IN ('L0', 'L1')",
            name="autonomous_risk_ceiling",
        ),
        sa.ForeignKeyConstraint(["engagement_id"], ["engagements.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("engagement_id", "name"),
    )
    op.create_index(op.f("ix_missions_engagement_id"), "missions", ["engagement_id"])
    op.create_index(op.f("ix_missions_state"), "missions", ["state"])
    op.create_index("ix_missions_state_updated", "missions", ["state", "updated_at"])

    op.create_table(
        "mission_runs",
        sa.Column("id", sa.String(length=36), nullable=False),
        sa.Column("engagement_id", sa.String(length=36), nullable=False),
        sa.Column("mission_id", sa.String(length=36), nullable=False),
        sa.Column("state", sa.String(length=32), nullable=False),
        sa.Column("cycle_index", sa.Integer(), nullable=False),
        sa.Column("worker_identity", sa.String(length=255), nullable=False),
        sa.Column("error_code", sa.String(length=255), nullable=True),
        sa.Column("started_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("heartbeat_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("ended_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("version", sa.Integer(), nullable=False),
        sa.CheckConstraint("cycle_index >= 0", name="cycle_index"),
        sa.CheckConstraint(
            "state IN ('running', 'interrupted', 'completed', 'failed')",
            name="state",
        ),
        sa.ForeignKeyConstraint(["engagement_id"], ["engagements.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["mission_id"], ["missions.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index(op.f("ix_mission_runs_engagement_id"), "mission_runs", ["engagement_id"])
    op.create_index(op.f("ix_mission_runs_mission_id"), "mission_runs", ["mission_id"])
    op.create_index(op.f("ix_mission_runs_state"), "mission_runs", ["state"])
    op.create_index("ix_mission_runs_mission_started", "mission_runs", ["mission_id", "started_at"])
    op.create_index("ix_mission_runs_state_heartbeat", "mission_runs", ["state", "heartbeat_at"])

    op.create_table(
        "agent_cycles",
        sa.Column("id", sa.String(length=36), nullable=False),
        sa.Column("engagement_id", sa.String(length=36), nullable=False),
        sa.Column("mission_run_id", sa.String(length=36), nullable=False),
        sa.Column("index", sa.Integer(), nullable=False),
        sa.Column("state", sa.String(length=32), nullable=False),
        sa.Column("leads_considered", sa.Integer(), nullable=False),
        sa.Column("actions_proposed", sa.Integer(), nullable=False),
        sa.Column("actions_executed", sa.Integer(), nullable=False),
        sa.Column("candidates_created", sa.Integer(), nullable=False),
        sa.Column("findings_created", sa.Integer(), nullable=False),
        sa.Column("error_code", sa.String(length=255), nullable=True),
        sa.Column("started_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("ended_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("version", sa.Integer(), nullable=False),
        sa.CheckConstraint("actions_executed <= actions_proposed", name="execution_bound"),
        sa.ForeignKeyConstraint(["engagement_id"], ["engagements.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["mission_run_id"], ["mission_runs.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("mission_run_id", "index"),
    )
    op.create_index(op.f("ix_agent_cycles_engagement_id"), "agent_cycles", ["engagement_id"])
    op.create_index(op.f("ix_agent_cycles_mission_run_id"), "agent_cycles", ["mission_run_id"])
    op.create_index(op.f("ix_agent_cycles_state"), "agent_cycles", ["state"])
    op.create_index("ix_agent_cycles_run_started", "agent_cycles", ["mission_run_id", "started_at"])

    op.create_table(
        "assets",
        sa.Column("id", sa.String(length=36), nullable=False),
        sa.Column("engagement_id", sa.String(length=36), nullable=False),
        sa.Column("kind", sa.String(length=32), nullable=False),
        sa.Column("identifier", sa.String(length=500), nullable=False),
        sa.Column("technologies", sa.JSON(), nullable=False),
        sa.Column("in_scope", sa.Boolean(), nullable=False),
        sa.Column("first_seen_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("last_seen_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("version", sa.Integer(), nullable=False),
        sa.ForeignKeyConstraint(["engagement_id"], ["engagements.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("engagement_id", "kind", "identifier"),
    )
    op.create_index(op.f("ix_assets_engagement_id"), "assets", ["engagement_id"])
    op.create_index(op.f("ix_assets_kind"), "assets", ["kind"])
    op.create_index("ix_assets_engagement_last_seen", "assets", ["engagement_id", "last_seen_at"])

    op.create_table(
        "endpoints",
        sa.Column("id", sa.String(length=36), nullable=False),
        sa.Column("engagement_id", sa.String(length=36), nullable=False),
        sa.Column("asset_id", sa.String(length=36), nullable=False),
        sa.Column("method", sa.String(length=16), nullable=False),
        sa.Column("path", sa.Text(), nullable=False),
        sa.Column("parameters", sa.JSON(), nullable=False),
        sa.Column("requires_authentication", sa.Boolean(), nullable=True),
        sa.Column("source", sa.String(length=64), nullable=False, server_default="discovery"),
        sa.Column("first_seen_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("last_seen_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("version", sa.Integer(), nullable=False),
        sa.ForeignKeyConstraint(["asset_id"], ["assets.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["engagement_id"], ["engagements.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("asset_id", "method", "path"),
    )
    op.create_index(op.f("ix_endpoints_engagement_id"), "endpoints", ["engagement_id"])
    op.create_index(op.f("ix_endpoints_asset_id"), "endpoints", ["asset_id"])
    op.create_index(
        "ix_endpoints_engagement_last_seen", "endpoints", ["engagement_id", "last_seen_at"]
    )

    op.create_table(
        "observations",
        sa.Column("id", sa.String(length=36), nullable=False),
        sa.Column("engagement_id", sa.String(length=36), nullable=False),
        sa.Column("kind", sa.String(length=32), nullable=False),
        sa.Column("subject", sa.Text(), nullable=False),
        sa.Column("digest", sa.String(length=64), nullable=False),
        sa.Column("summary", sa.Text(), nullable=False),
        sa.Column("evidence_id", sa.String(length=36), nullable=True),
        sa.Column("asset_id", sa.String(length=36), nullable=True),
        sa.Column("observed_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(["asset_id"], ["assets.id"], ondelete="SET NULL"),
        sa.ForeignKeyConstraint(["engagement_id"], ["engagements.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["evidence_id"], ["evidence.id"], ondelete="SET NULL"),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index(op.f("ix_observations_engagement_id"), "observations", ["engagement_id"])
    op.create_index(op.f("ix_observations_kind"), "observations", ["kind"])
    op.create_index(op.f("ix_observations_digest"), "observations", ["digest"])
    op.create_index(
        "ix_observations_engagement_observed", "observations", ["engagement_id", "observed_at"]
    )
    op.create_index("ix_observations_subject_kind", "observations", ["subject", "kind"])

    op.create_table(
        "leads",
        sa.Column("id", sa.String(length=36), nullable=False),
        sa.Column("engagement_id", sa.String(length=36), nullable=False),
        sa.Column("mission_id", sa.String(length=36), nullable=False),
        sa.Column("asset_id", sa.String(length=36), nullable=True),
        sa.Column("endpoint_id", sa.String(length=36), nullable=True),
        sa.Column("title", sa.String(length=500), nullable=False),
        sa.Column("hypothesis", sa.Text(), nullable=False),
        sa.Column("category", sa.String(length=255), nullable=False),
        sa.Column("confidence", sa.Float(), nullable=False),
        sa.Column("priority", sa.Integer(), nullable=False),
        sa.Column("status", sa.String(length=32), nullable=False),
        sa.Column("origin", sa.JSON(), nullable=False),
        sa.Column("evidence_ids", sa.JSON(), nullable=False),
        sa.Column("related_findings", sa.JSON(), nullable=False),
        sa.Column("attempt_count", sa.Integer(), nullable=False),
        sa.Column("failure_count", sa.Integer(), nullable=False),
        sa.Column("last_attempt_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("next_attempt_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("last_reasoning_summary", sa.Text(), nullable=True),
        sa.Column("next_action", sa.Text(), nullable=True),
        sa.Column("blocked_reason", sa.String(length=255), nullable=True),
        sa.Column("dedupe_key", sa.String(length=255), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("version", sa.Integer(), nullable=False),
        sa.CheckConstraint("confidence >= 0.0 AND confidence <= 1.0", name="confidence_range"),
        sa.CheckConstraint("failure_count <= attempt_count", name="failure_bound"),
        sa.CheckConstraint("priority >= 0 AND priority <= 100", name="priority_range"),
        sa.ForeignKeyConstraint(["asset_id"], ["assets.id"], ondelete="SET NULL"),
        sa.ForeignKeyConstraint(["endpoint_id"], ["endpoints.id"], ondelete="SET NULL"),
        sa.ForeignKeyConstraint(["engagement_id"], ["engagements.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["mission_id"], ["missions.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("mission_id", "dedupe_key"),
    )
    op.create_index(op.f("ix_leads_engagement_id"), "leads", ["engagement_id"])
    op.create_index(op.f("ix_leads_mission_id"), "leads", ["mission_id"])
    op.create_index(op.f("ix_leads_status"), "leads", ["status"])
    op.create_index("ix_leads_engagement_status", "leads", ["engagement_id", "status"])
    op.create_index("ix_leads_mission_priority", "leads", ["mission_id", "status", "priority"])
    op.create_index("ix_leads_next_attempt", "leads", ["mission_id", "next_attempt_at"])

    op.create_table(
        "candidates",
        sa.Column("id", sa.String(length=36), nullable=False),
        sa.Column("engagement_id", sa.String(length=36), nullable=False),
        sa.Column("source", sa.String(length=32), nullable=False),
        sa.Column("tool_name", sa.String(length=255), nullable=False),
        sa.Column("title", sa.String(length=500), nullable=False),
        sa.Column("category", sa.String(length=255), nullable=False),
        sa.Column("target", sa.Text(), nullable=False),
        sa.Column("raw_digest", sa.String(length=64), nullable=False),
        sa.Column("severity_hint", sa.String(length=32), nullable=True),
        sa.Column("lead_id", sa.String(length=36), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(["engagement_id"], ["engagements.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["lead_id"], ["leads.id"], ondelete="SET NULL"),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("engagement_id", "raw_digest"),
    )
    op.create_index(op.f("ix_candidates_engagement_id"), "candidates", ["engagement_id"])
    op.create_index(op.f("ix_candidates_source"), "candidates", ["source"])
    op.create_index(op.f("ix_candidates_raw_digest"), "candidates", ["raw_digest"])
    op.create_index(
        "ix_candidates_engagement_created", "candidates", ["engagement_id", "created_at"]
    )

    op.create_table(
        "surface_snapshots",
        sa.Column("id", sa.String(length=36), nullable=False),
        sa.Column("engagement_id", sa.String(length=36), nullable=False),
        sa.Column("digest", sa.String(length=64), nullable=False),
        sa.Column("asset_count", sa.Integer(), nullable=False),
        sa.Column("endpoint_count", sa.Integer(), nullable=False),
        sa.Column("captured_at", sa.DateTime(timezone=True), nullable=False),
        sa.CheckConstraint("asset_count >= 0 AND endpoint_count >= 0", name="counts"),
        sa.ForeignKeyConstraint(["engagement_id"], ["engagements.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index(
        op.f("ix_surface_snapshots_engagement_id"), "surface_snapshots", ["engagement_id"]
    )
    op.create_index(op.f("ix_surface_snapshots_digest"), "surface_snapshots", ["digest"])
    op.create_index(
        "ix_surface_snapshots_engagement_captured",
        "surface_snapshots",
        ["engagement_id", "captured_at"],
    )

    op.create_table(
        "change_events",
        sa.Column("id", sa.String(length=36), nullable=False),
        sa.Column("engagement_id", sa.String(length=36), nullable=False),
        sa.Column("snapshot_id", sa.String(length=36), nullable=False),
        sa.Column("kind", sa.String(length=32), nullable=False),
        sa.Column("subject", sa.Text(), nullable=False),
        sa.Column("previous_digest", sa.String(length=64), nullable=True),
        sa.Column("current_digest", sa.String(length=64), nullable=True),
        sa.Column("detected_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(["engagement_id"], ["engagements.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["snapshot_id"], ["surface_snapshots.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index(op.f("ix_change_events_engagement_id"), "change_events", ["engagement_id"])
    op.create_index(op.f("ix_change_events_snapshot_id"), "change_events", ["snapshot_id"])
    op.create_index(op.f("ix_change_events_kind"), "change_events", ["kind"])
    op.create_index(
        "ix_change_events_engagement_detected", "change_events", ["engagement_id", "detected_at"]
    )
    op.create_index("ix_change_events_subject_kind", "change_events", ["subject", "kind"])

    op.create_table(
        "budget_ledger",
        sa.Column("id", sa.String(length=36), nullable=False),
        sa.Column("mission_id", sa.String(length=36), nullable=False),
        sa.Column("window_kind", sa.String(length=16), nullable=False),
        sa.Column("scope_key", sa.String(length=255), nullable=False, server_default=""),
        sa.Column("window_start", sa.DateTime(timezone=True), nullable=False),
        sa.Column("request_count", sa.Integer(), nullable=False),
        sa.Column("token_count", sa.Integer(), nullable=False),
        sa.Column("version", sa.Integer(), nullable=False),
        sa.CheckConstraint("request_count >= 0 AND token_count >= 0", name="counters"),
        sa.CheckConstraint(
            "window_kind IN ('minute', 'hour', 'day', 'total')",
            name="window_kind",
        ),
        sa.ForeignKeyConstraint(["mission_id"], ["missions.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("mission_id", "window_kind", "scope_key", "window_start"),
    )
    op.create_index(op.f("ix_budget_ledger_mission_id"), "budget_ledger", ["mission_id"])
    op.create_index(
        "ix_budget_ledger_mission_window",
        "budget_ledger",
        ["mission_id", "window_kind", "window_start"],
    )


def downgrade() -> None:  # noqa: PLR0915 - mirrors upgrade in reverse order
    op.drop_index("ix_budget_ledger_mission_window", table_name="budget_ledger")
    op.drop_index(op.f("ix_budget_ledger_mission_id"), table_name="budget_ledger")
    op.drop_table("budget_ledger")

    op.drop_index("ix_change_events_subject_kind", table_name="change_events")
    op.drop_index("ix_change_events_engagement_detected", table_name="change_events")
    op.drop_index(op.f("ix_change_events_kind"), table_name="change_events")
    op.drop_index(op.f("ix_change_events_snapshot_id"), table_name="change_events")
    op.drop_index(op.f("ix_change_events_engagement_id"), table_name="change_events")
    op.drop_table("change_events")

    op.drop_index("ix_surface_snapshots_engagement_captured", table_name="surface_snapshots")
    op.drop_index(op.f("ix_surface_snapshots_digest"), table_name="surface_snapshots")
    op.drop_index(op.f("ix_surface_snapshots_engagement_id"), table_name="surface_snapshots")
    op.drop_table("surface_snapshots")

    op.drop_index("ix_candidates_engagement_created", table_name="candidates")
    op.drop_index(op.f("ix_candidates_raw_digest"), table_name="candidates")
    op.drop_index(op.f("ix_candidates_source"), table_name="candidates")
    op.drop_index(op.f("ix_candidates_engagement_id"), table_name="candidates")
    op.drop_table("candidates")

    op.drop_index("ix_leads_next_attempt", table_name="leads")
    op.drop_index("ix_leads_mission_priority", table_name="leads")
    op.drop_index("ix_leads_engagement_status", table_name="leads")
    op.drop_index(op.f("ix_leads_status"), table_name="leads")
    op.drop_index(op.f("ix_leads_mission_id"), table_name="leads")
    op.drop_index(op.f("ix_leads_engagement_id"), table_name="leads")
    op.drop_table("leads")

    op.drop_index("ix_observations_subject_kind", table_name="observations")
    op.drop_index("ix_observations_engagement_observed", table_name="observations")
    op.drop_index(op.f("ix_observations_digest"), table_name="observations")
    op.drop_index(op.f("ix_observations_kind"), table_name="observations")
    op.drop_index(op.f("ix_observations_engagement_id"), table_name="observations")
    op.drop_table("observations")

    op.drop_index("ix_endpoints_engagement_last_seen", table_name="endpoints")
    op.drop_index(op.f("ix_endpoints_asset_id"), table_name="endpoints")
    op.drop_index(op.f("ix_endpoints_engagement_id"), table_name="endpoints")
    op.drop_table("endpoints")

    op.drop_index("ix_assets_engagement_last_seen", table_name="assets")
    op.drop_index(op.f("ix_assets_kind"), table_name="assets")
    op.drop_index(op.f("ix_assets_engagement_id"), table_name="assets")
    op.drop_table("assets")

    op.drop_index("ix_agent_cycles_run_started", table_name="agent_cycles")
    op.drop_index(op.f("ix_agent_cycles_state"), table_name="agent_cycles")
    op.drop_index(op.f("ix_agent_cycles_mission_run_id"), table_name="agent_cycles")
    op.drop_index(op.f("ix_agent_cycles_engagement_id"), table_name="agent_cycles")
    op.drop_table("agent_cycles")

    op.drop_index("ix_mission_runs_state_heartbeat", table_name="mission_runs")
    op.drop_index("ix_mission_runs_mission_started", table_name="mission_runs")
    op.drop_index(op.f("ix_mission_runs_state"), table_name="mission_runs")
    op.drop_index(op.f("ix_mission_runs_mission_id"), table_name="mission_runs")
    op.drop_index(op.f("ix_mission_runs_engagement_id"), table_name="mission_runs")
    op.drop_table("mission_runs")

    op.drop_index("ix_missions_state_updated", table_name="missions")
    op.drop_index(op.f("ix_missions_state"), table_name="missions")
    op.drop_index(op.f("ix_missions_engagement_id"), table_name="missions")
    op.drop_table("missions")

    op.drop_column("engagement_scopes", "denied_wildcards")
    op.drop_column("engagement_scopes", "allowed_wildcards")
