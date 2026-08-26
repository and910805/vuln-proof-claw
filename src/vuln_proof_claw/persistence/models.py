"""Relational mappings for Phase 0 domain entities."""

from __future__ import annotations

from datetime import datetime

from sqlalchemy import (
    JSON,
    BigInteger,
    Boolean,
    CheckConstraint,
    Column,
    DateTime,
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
    sequence: Mapped[int] = mapped_column(Integer, nullable=False, server_default="0")
    state: Mapped[str] = mapped_column(String(32), nullable=False, server_default="planned")
    attempts: Mapped[int] = mapped_column(Integer, nullable=False, server_default="0")


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
        "role",
        String(16),
        nullable=False,
        server_default="payload",
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
    cwe_id: Mapped[str | None] = mapped_column(String(16), nullable=True)
    verification_method: Mapped[str] = mapped_column(
        String(32), nullable=False, server_default="observed"
    )
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


class UsageSampleRecord(Base):
    __tablename__ = "usage_samples"
    __table_args__ = (
        Index("ix_usage_samples_engagement_recorded", "engagement_id", "recorded_at"),
        CheckConstraint("quantity >= 0", name="quantity"),
        CheckConstraint("input_tokens >= 0", name="input_tokens"),
        CheckConstraint("output_tokens >= 0", name="output_tokens"),
        CheckConstraint("cost_micros >= 0", name="cost_micros"),
        CheckConstraint("wall_milliseconds >= 0", name="wall_milliseconds"),
    )

    id: Mapped[str] = mapped_column(String(ID_LENGTH), primary_key=True)
    engagement_id: Mapped[str] = mapped_column(
        ForeignKey("engagements.id", ondelete="CASCADE"),
        index=True,
    )
    action_id: Mapped[str | None] = mapped_column(
        ForeignKey("actions.id", ondelete="SET NULL"),
        nullable=True,
    )
    kind: Mapped[str] = mapped_column(String(32), index=True)
    recorded_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    quantity: Mapped[int] = mapped_column(Integer, nullable=False, default=1)
    input_tokens: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    output_tokens: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    cost_micros: Mapped[int] = mapped_column(BigInteger, nullable=False, default=0)
    wall_milliseconds: Mapped[int] = mapped_column(BigInteger, nullable=False, default=0)
    engine: Mapped[str] = mapped_column(String(64), nullable=False, default="")
    model: Mapped[str] = mapped_column(String(128), nullable=False, default="")


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
