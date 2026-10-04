"""Relational mappings for Phase 0 domain entities."""

from __future__ import annotations

from datetime import datetime

from sqlalchemy import (
    JSON,
    Boolean,
    CheckConstraint,
    Column,
    DateTime,
    Float,
    ForeignKey,
    Index,
    Integer,
    LargeBinary,
    String,
    Table,
    Text,
    UniqueConstraint,
)
from sqlalchemy.orm import Mapped, mapped_column

from vuln_proof_claw.persistence.base import Base

ID_LENGTH = 36
DIGEST_LENGTH = 64


class ProjectRecord(Base):
    __tablename__ = "projects"

    id: Mapped[str] = mapped_column(String(ID_LENGTH), primary_key=True)
    name: Mapped[str] = mapped_column(String(255))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))


class EngagementRecord(Base):
    __tablename__ = "engagements"
    __table_args__ = (Index("ix_engagements_project_created", "project_id", "created_at"),)
    id: Mapped[str] = mapped_column(String(ID_LENGTH), primary_key=True)
    project_id: Mapped[str] = mapped_column(
        ForeignKey("projects.id", ondelete="RESTRICT"),
        index=True,
    )
    name: Mapped[str] = mapped_column(String(255))
    starts_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    ends_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    maximum_risk: Mapped[str] = mapped_column(String(2))
    auto_execute_l1: Mapped[bool] = mapped_column(Boolean, default=False)
    destructive_actions_enabled: Mapped[bool] = mapped_column(Boolean, default=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    version: Mapped[int] = mapped_column(Integer, nullable=False, default=1)
    __mapper_args__ = {"version_id_col": version}  # noqa: RUF012


class EngagementScopeRecord(Base):
    __tablename__ = "engagement_scopes"

    engagement_id: Mapped[str] = mapped_column(
        ForeignKey("engagements.id", ondelete="CASCADE"),
        primary_key=True,
    )
    allowed_hostnames: Mapped[list[str]] = mapped_column(JSON)
    allowed_cidrs: Mapped[list[str]] = mapped_column(JSON)
    allowed_ports: Mapped[list[int]] = mapped_column(JSON)
    allowed_schemes: Mapped[list[str]] = mapped_column(JSON)
    allowed_paths: Mapped[list[str]] = mapped_column(JSON)
    denied_hostnames: Mapped[list[str]] = mapped_column(JSON)
    denied_cidrs: Mapped[list[str]] = mapped_column(JSON)
    denied_paths: Mapped[list[str]] = mapped_column(JSON)
    allowed_wildcards: Mapped[list[str]] = mapped_column(JSON, nullable=False, default=list)
    denied_wildcards: Mapped[list[str]] = mapped_column(JSON, nullable=False, default=list)
    valid_from: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    valid_until: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)


class FlowRecord(Base):
    __tablename__ = "flows"
    __table_args__ = (Index("ix_flows_engagement_created", "engagement_id", "created_at"),)
    id: Mapped[str] = mapped_column(String(ID_LENGTH), primary_key=True)
    engagement_id: Mapped[str] = mapped_column(
        ForeignKey("engagements.id", ondelete="CASCADE"),
        index=True,
    )
    objective: Mapped[str] = mapped_column(Text)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    version: Mapped[int] = mapped_column(Integer, nullable=False, default=1)
    __mapper_args__ = {"version_id_col": version}  # noqa: RUF012


class TaskRecord(Base):
    __tablename__ = "tasks"
    __table_args__ = (Index("ix_tasks_flow_created", "flow_id", "created_at"),)

    id: Mapped[str] = mapped_column(String(ID_LENGTH), primary_key=True)
    flow_id: Mapped[str] = mapped_column(ForeignKey("flows.id", ondelete="CASCADE"), index=True)
    title: Mapped[str] = mapped_column(String(500))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))


class ApprovalRecord(Base):
    __tablename__ = "approvals"
    __table_args__ = (Index("ix_approvals_engagement_expires", "engagement_id", "expires_at"),)
    id: Mapped[str] = mapped_column(String(ID_LENGTH), primary_key=True)
    engagement_id: Mapped[str] = mapped_column(
        ForeignKey("engagements.id", ondelete="CASCADE"),
        index=True,
    )
    action_type: Mapped[str] = mapped_column(String(255))
    normalized_target: Mapped[str] = mapped_column(Text)
    parameter_digest: Mapped[str] = mapped_column(String(DIGEST_LENGTH))
    risk_level: Mapped[str] = mapped_column(String(2))
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    permitted_executions: Mapped[int] = mapped_column(Integer)
    approver: Mapped[str] = mapped_column(String(320))
    approved_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    consumed_executions: Mapped[int] = mapped_column(Integer, default=0)
    version: Mapped[int] = mapped_column(Integer, nullable=False, default=1)
    __mapper_args__ = {"version_id_col": version}  # noqa: RUF012


class ApprovalPresetRecord(Base):
    """Reusable approver-authored policy that still emits exact one-action approvals."""

    __tablename__ = "approval_presets"
    __table_args__ = (
        UniqueConstraint("engagement_id", "name"),
        Index("ix_approval_presets_engagement_enabled", "engagement_id", "enabled"),
    )
    id: Mapped[str] = mapped_column(String(ID_LENGTH), primary_key=True)
    engagement_id: Mapped[str] = mapped_column(
        ForeignKey("engagements.id", ondelete="CASCADE"), index=True
    )
    name: Mapped[str] = mapped_column(String(255))
    action_types: Mapped[list[str]] = mapped_column(JSON)
    target_prefixes: Mapped[list[str]] = mapped_column(JSON)
    maximum_risk: Mapped[str] = mapped_column(String(2))
    approval_ttl_seconds: Mapped[int] = mapped_column(Integer)
    enabled: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)
    created_by: Mapped[str] = mapped_column(String(320))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    version: Mapped[int] = mapped_column(Integer, nullable=False, default=1)
    __mapper_args__ = {"version_id_col": version}  # noqa: RUF012


class ActionRecord(Base):
    __tablename__ = "actions"
    __table_args__ = (
        UniqueConstraint("engagement_id", "idempotency_key"),
        Index("ix_actions_engagement_state", "engagement_id", "state"),
        Index("ix_actions_task_created", "task_id", "created_at"),
    )
    id: Mapped[str] = mapped_column(String(ID_LENGTH), primary_key=True)
    engagement_id: Mapped[str] = mapped_column(
        ForeignKey("engagements.id", ondelete="CASCADE"),
        index=True,
    )
    task_id: Mapped[str] = mapped_column(ForeignKey("tasks.id", ondelete="CASCADE"), index=True)
    action_type: Mapped[str] = mapped_column(String(255))
    normalized_target: Mapped[str] = mapped_column(Text)
    parameter_digest: Mapped[str] = mapped_column(String(DIGEST_LENGTH))
    risk_level: Mapped[str] = mapped_column(String(2))
    idempotency_key: Mapped[str] = mapped_column(String(255))
    state: Mapped[str] = mapped_column(String(32), index=True)
    approval_id: Mapped[str | None] = mapped_column(
        ForeignKey("approvals.id", ondelete="RESTRICT"),
        nullable=True,
    )
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    started_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    completed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    version: Mapped[int] = mapped_column(Integer, nullable=False, default=1)
    __mapper_args__ = {"version_id_col": version}  # noqa: RUF012


class WorkerExecutionRecord(Base):
    __tablename__ = "worker_executions"
    __table_args__ = (
        UniqueConstraint("request_id"),
        UniqueConstraint("action_id"),
        Index("ix_worker_executions_engagement_state", "engagement_id", "state"),
        CheckConstraint(
            "state IN ('starting', 'running', 'completed', 'failed', "
            "'timed_out', 'cancelled', 'lost')",
            name="state",
        ),
        CheckConstraint(
            "NOT cleaned_up OR state IN ('completed', 'failed', 'timed_out', 'cancelled', 'lost')",
            name="cleanup_terminal",
        ),
    )

    id: Mapped[str] = mapped_column(String(ID_LENGTH), primary_key=True)
    request_id: Mapped[str] = mapped_column(String(255))
    engagement_id: Mapped[str] = mapped_column(
        ForeignKey("engagements.id", ondelete="CASCADE"),
        index=True,
    )
    action_id: Mapped[str] = mapped_column(
        ForeignKey("actions.id", ondelete="CASCADE"),
        index=True,
    )
    runtime_identity: Mapped[str] = mapped_column(String(500))
    state: Mapped[str] = mapped_column(String(32), index=True)
    cleaned_up: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    error_code: Mapped[str | None] = mapped_column(String(255), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    version: Mapped[int] = mapped_column(Integer, nullable=False, default=1)
    __mapper_args__ = {"version_id_col": version}  # noqa: RUF012


class EvidenceRecord(Base):
    __tablename__ = "evidence"
    __table_args__ = (
        Index("ix_evidence_action_captured", "action_id", "captured_at"),
        UniqueConstraint("action_id", "digest"),
    )

    id: Mapped[str] = mapped_column(String(ID_LENGTH), primary_key=True)
    action_id: Mapped[str] = mapped_column(
        ForeignKey("actions.id", ondelete="CASCADE"),
        index=True,
    )
    tool_name: Mapped[str] = mapped_column(String(255))
    tool_version: Mapped[str] = mapped_column(String(128))
    digest: Mapped[str] = mapped_column(String(DIGEST_LENGTH), index=True)
    previous_digest: Mapped[str | None] = mapped_column(String(DIGEST_LENGTH), nullable=True)
    captured_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))


class EvidencePayloadRecord(Base):
    __tablename__ = "evidence_payloads"
    __table_args__ = (
        UniqueConstraint("engagement_id", "chain_index"),
        Index("ix_evidence_payloads_engagement_chain", "engagement_id", "chain_index"),
        CheckConstraint("raw_size >= 0", name="raw_size"),
    )

    evidence_id: Mapped[str] = mapped_column(
        ForeignKey("evidence.id", ondelete="CASCADE"),
        primary_key=True,
    )
    engagement_id: Mapped[str] = mapped_column(
        ForeignKey("engagements.id", ondelete="CASCADE"),
        index=True,
    )
    chain_index: Mapped[int] = mapped_column(Integer)
    canonical_metadata: Mapped[bytes] = mapped_column(LargeBinary)
    raw_content: Mapped[bytes] = mapped_column(LargeBinary)
    raw_size: Mapped[int] = mapped_column(Integer)


class ArtifactRecord(Base):
    __tablename__ = "artifacts"

    id: Mapped[str] = mapped_column(String(ID_LENGTH), primary_key=True)
    action_id: Mapped[str] = mapped_column(
        ForeignKey("actions.id", ondelete="CASCADE"),
        index=True,
    )
    kind: Mapped[str] = mapped_column(String(32))
    media_type: Mapped[str] = mapped_column(String(255))
    storage_reference: Mapped[str] = mapped_column(Text)
    digest: Mapped[str] = mapped_column(String(DIGEST_LENGTH), index=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))


class ReportExportRecord(Base):
    __tablename__ = "report_exports"
    __table_args__ = (
        UniqueConstraint("engagement_id", "idempotency_key"),
        Index("ix_report_exports_engagement_created", "engagement_id", "created_at"),
        CheckConstraint("size >= 0", name="size"),
        CheckConstraint("format IN ('json', 'markdown', 'sarif')", name="format"),
    )

    id: Mapped[str] = mapped_column(String(ID_LENGTH), primary_key=True)
    engagement_id: Mapped[str] = mapped_column(
        ForeignKey("engagements.id", ondelete="CASCADE"), index=True
    )
    format: Mapped[str] = mapped_column(String(16))
    media_type: Mapped[str] = mapped_column(String(255))
    digest: Mapped[str] = mapped_column(String(DIGEST_LENGTH), index=True)
    size: Mapped[int] = mapped_column(Integer)
    idempotency_key: Mapped[str] = mapped_column(String(255))
    content: Mapped[bytes] = mapped_column(LargeBinary)
    created_by: Mapped[str] = mapped_column(String(320))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))


finding_evidence = Table(
    "finding_evidence",
    Base.metadata,
    Column(
        "finding_id",
        String(ID_LENGTH),
        ForeignKey("findings.id", ondelete="CASCADE"),
        primary_key=True,
    ),
    Column(
        "evidence_id",
        String(ID_LENGTH),
        ForeignKey("evidence.id", ondelete="RESTRICT"),
        primary_key=True,
    ),
)


class FindingRecord(Base):
    __tablename__ = "findings"
    __table_args__ = (Index("ix_findings_engagement_status", "engagement_id", "status"),)
    id: Mapped[str] = mapped_column(String(ID_LENGTH), primary_key=True)
    engagement_id: Mapped[str] = mapped_column(
        ForeignKey("engagements.id", ondelete="CASCADE"),
        index=True,
    )
    title: Mapped[str] = mapped_column(String(500))
    vulnerability_class: Mapped[str] = mapped_column(String(255))
    affected_target: Mapped[str] = mapped_column(Text)
    status: Mapped[str] = mapped_column(String(32), index=True)
    severity: Mapped[str] = mapped_column(
        String(32), nullable=False, server_default="informational"
    )
    confidence: Mapped[str] = mapped_column(String(32), nullable=False, server_default="medium")
    remediation: Mapped[str] = mapped_column(
        Text,
        nullable=False,
        server_default="Review the evidence and apply the relevant security control.",
    )
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    version: Mapped[int] = mapped_column(Integer, nullable=False, default=1)
    __mapper_args__ = {"version_id_col": version}  # noqa: RUF012


class MissionRecord(Base):
    """A persistent autonomous research campaign bound to one engagement."""

    __tablename__ = "missions"
    __table_args__ = (
        UniqueConstraint("engagement_id", "name"),
        Index("ix_missions_state_updated", "state", "updated_at"),
        CheckConstraint(
            "maximum_autonomous_risk IN ('L0', 'L1')",
            name="autonomous_risk_ceiling",
        ),
    )

    id: Mapped[str] = mapped_column(String(ID_LENGTH), primary_key=True)
    engagement_id: Mapped[str] = mapped_column(
        ForeignKey("engagements.id", ondelete="CASCADE"), index=True
    )
    name: Mapped[str] = mapped_column(String(255))
    state: Mapped[str] = mapped_column(String(32), index=True)
    maximum_autonomous_risk: Mapped[str] = mapped_column(String(2))
    kill_switch_engaged: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    cadence: Mapped[dict[str, int]] = mapped_column(JSON)
    budget: Mapped[dict[str, int]] = mapped_column(JSON)
    expires_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    version: Mapped[int] = mapped_column(Integer, nullable=False, default=1)
    __mapper_args__ = {"version_id_col": version}  # noqa: RUF012


class MissionRunRecord(Base):
    """One continuous, crash-recoverable execution span of a mission."""

    __tablename__ = "mission_runs"
    __table_args__ = (
        Index("ix_mission_runs_mission_started", "mission_id", "started_at"),
        Index("ix_mission_runs_state_heartbeat", "state", "heartbeat_at"),
        CheckConstraint(
            "state IN ('running', 'interrupted', 'completed', 'failed')",
            name="state",
        ),
        CheckConstraint("cycle_index >= 0", name="cycle_index"),
    )

    id: Mapped[str] = mapped_column(String(ID_LENGTH), primary_key=True)
    engagement_id: Mapped[str] = mapped_column(
        ForeignKey("engagements.id", ondelete="CASCADE"), index=True
    )
    mission_id: Mapped[str] = mapped_column(
        ForeignKey("missions.id", ondelete="CASCADE"), index=True
    )
    state: Mapped[str] = mapped_column(String(32), index=True)
    cycle_index: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    worker_identity: Mapped[str] = mapped_column(String(255))
    error_code: Mapped[str | None] = mapped_column(String(255), nullable=True)
    started_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    heartbeat_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    ended_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    version: Mapped[int] = mapped_column(Integer, nullable=False, default=1)
    __mapper_args__ = {"version_id_col": version}  # noqa: RUF012


class AgentCycleRecord(Base):
    """One observe, plan, act, and verify iteration."""

    __tablename__ = "agent_cycles"
    __table_args__ = (
        UniqueConstraint("mission_run_id", "index"),
        Index("ix_agent_cycles_run_started", "mission_run_id", "started_at"),
        CheckConstraint("actions_executed <= actions_proposed", name="execution_bound"),
    )

    id: Mapped[str] = mapped_column(String(ID_LENGTH), primary_key=True)
    engagement_id: Mapped[str] = mapped_column(
        ForeignKey("engagements.id", ondelete="CASCADE"), index=True
    )
    mission_run_id: Mapped[str] = mapped_column(
        ForeignKey("mission_runs.id", ondelete="CASCADE"), index=True
    )
    index: Mapped[int] = mapped_column(Integer, nullable=False)
    state: Mapped[str] = mapped_column(String(32), index=True)
    leads_considered: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    actions_proposed: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    actions_executed: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    candidates_created: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    findings_created: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    error_code: Mapped[str | None] = mapped_column(String(255), nullable=True)
    started_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    ended_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    version: Mapped[int] = mapped_column(Integer, nullable=False, default=1)
    __mapper_args__ = {"version_id_col": version}  # noqa: RUF012


class AssetRecord(Base):
    """A discovered host, address, service, or application."""

    __tablename__ = "assets"
    __table_args__ = (
        UniqueConstraint("engagement_id", "kind", "identifier"),
        Index("ix_assets_engagement_last_seen", "engagement_id", "last_seen_at"),
    )

    id: Mapped[str] = mapped_column(String(ID_LENGTH), primary_key=True)
    engagement_id: Mapped[str] = mapped_column(
        ForeignKey("engagements.id", ondelete="CASCADE"), index=True
    )
    kind: Mapped[str] = mapped_column(String(32), index=True)
    identifier: Mapped[str] = mapped_column(String(500))
    technologies: Mapped[list[str]] = mapped_column(JSON, nullable=False, default=list)
    in_scope: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)
    first_seen_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    last_seen_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    version: Mapped[int] = mapped_column(Integer, nullable=False, default=1)
    __mapper_args__ = {"version_id_col": version}  # noqa: RUF012


class EndpointRecord(Base):
    """A discovered request surface belonging to an asset."""

    __tablename__ = "endpoints"
    __table_args__ = (
        UniqueConstraint("asset_id", "method", "path"),
        Index("ix_endpoints_engagement_last_seen", "engagement_id", "last_seen_at"),
    )

    id: Mapped[str] = mapped_column(String(ID_LENGTH), primary_key=True)
    engagement_id: Mapped[str] = mapped_column(
        ForeignKey("engagements.id", ondelete="CASCADE"), index=True
    )
    asset_id: Mapped[str] = mapped_column(ForeignKey("assets.id", ondelete="CASCADE"), index=True)
    method: Mapped[str] = mapped_column(String(16))
    path: Mapped[str] = mapped_column(Text)
    parameters: Mapped[list[str]] = mapped_column(JSON, nullable=False, default=list)
    requires_authentication: Mapped[bool | None] = mapped_column(Boolean, nullable=True)
    source: Mapped[str] = mapped_column(String(64), nullable=False, server_default="discovery")
    first_seen_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    last_seen_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    version: Mapped[int] = mapped_column(Integer, nullable=False, default=1)
    __mapper_args__ = {"version_id_col": version}  # noqa: RUF012


class ObservationRecord(Base):
    """An immutable recorded phenomenon, optionally backed by stored evidence."""

    __tablename__ = "observations"
    __table_args__ = (
        Index("ix_observations_engagement_observed", "engagement_id", "observed_at"),
        Index("ix_observations_subject_kind", "subject", "kind"),
    )

    id: Mapped[str] = mapped_column(String(ID_LENGTH), primary_key=True)
    engagement_id: Mapped[str] = mapped_column(
        ForeignKey("engagements.id", ondelete="CASCADE"), index=True
    )
    kind: Mapped[str] = mapped_column(String(32), index=True)
    subject: Mapped[str] = mapped_column(Text)
    digest: Mapped[str] = mapped_column(String(DIGEST_LENGTH), index=True)
    summary: Mapped[str] = mapped_column(Text)
    evidence_id: Mapped[str | None] = mapped_column(
        ForeignKey("evidence.id", ondelete="SET NULL"), nullable=True
    )
    asset_id: Mapped[str | None] = mapped_column(
        ForeignKey("assets.id", ondelete="SET NULL"), nullable=True
    )
    observed_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))


class LeadRecord(Base):
    """A testable research hypothesis under autonomous investigation."""

    __tablename__ = "leads"
    __table_args__ = (
        UniqueConstraint("mission_id", "dedupe_key"),
        Index("ix_leads_engagement_status", "engagement_id", "status"),
        Index("ix_leads_mission_priority", "mission_id", "status", "priority"),
        Index("ix_leads_next_attempt", "mission_id", "next_attempt_at"),
        CheckConstraint("confidence >= 0.0 AND confidence <= 1.0", name="confidence_range"),
        CheckConstraint("priority >= 0 AND priority <= 100", name="priority_range"),
        CheckConstraint("failure_count <= attempt_count", name="failure_bound"),
    )

    id: Mapped[str] = mapped_column(String(ID_LENGTH), primary_key=True)
    engagement_id: Mapped[str] = mapped_column(
        ForeignKey("engagements.id", ondelete="CASCADE"), index=True
    )
    mission_id: Mapped[str] = mapped_column(
        ForeignKey("missions.id", ondelete="CASCADE"), index=True
    )
    asset_id: Mapped[str | None] = mapped_column(
        ForeignKey("assets.id", ondelete="SET NULL"), nullable=True
    )
    endpoint_id: Mapped[str | None] = mapped_column(
        ForeignKey("endpoints.id", ondelete="SET NULL"), nullable=True
    )
    title: Mapped[str] = mapped_column(String(500))
    hypothesis: Mapped[str] = mapped_column(Text)
    category: Mapped[str] = mapped_column(String(255))
    confidence: Mapped[float] = mapped_column(Float, nullable=False, default=0.5)
    priority: Mapped[int] = mapped_column(Integer, nullable=False, default=50)
    status: Mapped[str] = mapped_column(String(32), index=True)
    origin: Mapped[list[str]] = mapped_column(JSON, nullable=False, default=list)
    evidence_ids: Mapped[list[str]] = mapped_column(JSON, nullable=False, default=list)
    related_findings: Mapped[list[str]] = mapped_column(JSON, nullable=False, default=list)
    attempt_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    failure_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    last_attempt_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    next_attempt_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    last_reasoning_summary: Mapped[str | None] = mapped_column(Text, nullable=True)
    next_action: Mapped[str | None] = mapped_column(Text, nullable=True)
    blocked_reason: Mapped[str | None] = mapped_column(String(255), nullable=True)
    dedupe_key: Mapped[str | None] = mapped_column(String(255), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    version: Mapped[int] = mapped_column(Integer, nullable=False, default=1)
    __mapper_args__ = {"version_id_col": version}  # noqa: RUF012


class CandidateRecord(Base):
    """A scanner or heuristic signal awaiting Planner triage."""

    __tablename__ = "candidates"
    __table_args__ = (
        UniqueConstraint("engagement_id", "raw_digest"),
        Index("ix_candidates_engagement_created", "engagement_id", "created_at"),
    )

    id: Mapped[str] = mapped_column(String(ID_LENGTH), primary_key=True)
    engagement_id: Mapped[str] = mapped_column(
        ForeignKey("engagements.id", ondelete="CASCADE"), index=True
    )
    source: Mapped[str] = mapped_column(String(32), index=True)
    tool_name: Mapped[str] = mapped_column(String(255))
    title: Mapped[str] = mapped_column(String(500))
    category: Mapped[str] = mapped_column(String(255))
    target: Mapped[str] = mapped_column(Text)
    raw_digest: Mapped[str] = mapped_column(String(DIGEST_LENGTH), index=True)
    severity_hint: Mapped[str | None] = mapped_column(String(32), nullable=True)
    lead_id: Mapped[str | None] = mapped_column(
        ForeignKey("leads.id", ondelete="SET NULL"), nullable=True
    )
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))


class SurfaceSnapshotRecord(Base):
    """A content digest of the known attack surface at one point in time."""

    __tablename__ = "surface_snapshots"
    __table_args__ = (
        Index("ix_surface_snapshots_engagement_captured", "engagement_id", "captured_at"),
        CheckConstraint("asset_count >= 0 AND endpoint_count >= 0", name="counts"),
    )

    id: Mapped[str] = mapped_column(String(ID_LENGTH), primary_key=True)
    engagement_id: Mapped[str] = mapped_column(
        ForeignKey("engagements.id", ondelete="CASCADE"), index=True
    )
    digest: Mapped[str] = mapped_column(String(DIGEST_LENGTH), index=True)
    asset_count: Mapped[int] = mapped_column(Integer, nullable=False)
    endpoint_count: Mapped[int] = mapped_column(Integer, nullable=False)
    captured_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))


class ChangeEventRecord(Base):
    """A typed difference between two attack-surface snapshots."""

    __tablename__ = "change_events"
    __table_args__ = (
        Index("ix_change_events_engagement_detected", "engagement_id", "detected_at"),
        Index("ix_change_events_subject_kind", "subject", "kind"),
    )

    id: Mapped[str] = mapped_column(String(ID_LENGTH), primary_key=True)
    engagement_id: Mapped[str] = mapped_column(
        ForeignKey("engagements.id", ondelete="CASCADE"), index=True
    )
    snapshot_id: Mapped[str] = mapped_column(
        ForeignKey("surface_snapshots.id", ondelete="CASCADE"), index=True
    )
    kind: Mapped[str] = mapped_column(String(32), index=True)
    subject: Mapped[str] = mapped_column(Text)
    previous_digest: Mapped[str | None] = mapped_column(String(DIGEST_LENGTH), nullable=True)
    current_digest: Mapped[str | None] = mapped_column(String(DIGEST_LENGTH), nullable=True)
    detected_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))


class BudgetLedgerRecord(Base):
    """Deterministic request and token counters for one mission window."""

    __tablename__ = "budget_ledger"
    __table_args__ = (
        UniqueConstraint("mission_id", "window_kind", "scope_key", "window_start"),
        Index("ix_budget_ledger_mission_window", "mission_id", "window_kind", "window_start"),
        CheckConstraint(
            "window_kind IN ('minute', 'hour', 'day', 'total')",
            name="window_kind",
        ),
        CheckConstraint("request_count >= 0 AND token_count >= 0", name="counters"),
    )

    id: Mapped[str] = mapped_column(String(ID_LENGTH), primary_key=True)
    mission_id: Mapped[str] = mapped_column(
        ForeignKey("missions.id", ondelete="CASCADE"), index=True
    )
    window_kind: Mapped[str] = mapped_column(String(16))
    scope_key: Mapped[str] = mapped_column(String(255), nullable=False, server_default="")
    window_start: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    request_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    token_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    version: Mapped[int] = mapped_column(Integer, nullable=False, default=1)
    __mapper_args__ = {"version_id_col": version}  # noqa: RUF012


class AuditEventRecord(Base):
    __tablename__ = "audit_events"
    __table_args__ = (Index("ix_audit_events_engagement_created", "engagement_id", "created_at"),)

    id: Mapped[str] = mapped_column(String(ID_LENGTH), primary_key=True)
    engagement_id: Mapped[str | None] = mapped_column(
        ForeignKey("engagements.id", ondelete="SET NULL"),
        nullable=True,
    )
    event_type: Mapped[str] = mapped_column(String(255))
    actor: Mapped[str] = mapped_column(String(320))
    payload: Mapped[bytes] = mapped_column(LargeBinary)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
