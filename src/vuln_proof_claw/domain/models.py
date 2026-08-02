"""Framework-independent domain value objects."""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from datetime import UTC, datetime

from vuln_proof_claw.domain.enums import (
    ActionState,
    ArtifactKind,
    FindingConfidence,
    FindingSeverity,
    FindingStatus,
    ReportFormat,
    RiskLevel,
    WorkerState,
)
from vuln_proof_claw.domain.errors import DomainValidationError
from vuln_proof_claw.domain.identifiers import (
    ActionId,
    ApprovalId,
    ArtifactId,
    AuditEventId,
    EngagementId,
    EvidenceId,
    FindingId,
    FlowId,
    ProjectId,
    ReportExportId,
    TaskId,
    WorkerId,
    new_action_id,
    new_approval_id,
    new_artifact_id,
    new_audit_event_id,
    new_engagement_id,
    new_evidence_id,
    new_finding_id,
    new_flow_id,
    new_project_id,
    new_report_export_id,
    new_task_id,
    new_worker_id,
)

_SHA256_PATTERN = re.compile(r"^[a-f0-9]{64}$")


def utc_now() -> datetime:
    """Return a timezone-aware UTC timestamp."""
    return datetime.now(UTC)


def _require_text(value: str, field_name: str) -> None:
    if not value.strip():
        raise DomainValidationError(f"{field_name} must not be empty")


def _require_aware(value: datetime, field_name: str) -> None:
    if value.tzinfo is None or value.utcoffset() is None:
        raise DomainValidationError(f"{field_name} must be timezone-aware")


def _require_sha256(value: str, field_name: str) -> None:
    if not _SHA256_PATTERN.fullmatch(value):
        raise DomainValidationError(f"{field_name} must be a lowercase SHA-256 digest")


@dataclass(frozen=True, slots=True)
class Project:
    """Top-level customer, product, or research boundary."""

    name: str
    id: ProjectId = field(default_factory=new_project_id)
    created_at: datetime = field(default_factory=utc_now)

    def __post_init__(self) -> None:
        _require_text(self.name, "name")
        _require_aware(self.created_at, "created_at")


@dataclass(frozen=True, slots=True)
class Engagement:
    """Time-bounded, explicitly scoped security assessment."""

    project_id: ProjectId
    name: str
    starts_at: datetime
    ends_at: datetime
    maximum_risk: RiskLevel = RiskLevel.L3
    destructive_actions_enabled: bool = False
    id: EngagementId = field(default_factory=new_engagement_id)
    created_at: datetime = field(default_factory=utc_now)

    def __post_init__(self) -> None:
        _require_text(self.name, "name")
        _require_aware(self.starts_at, "starts_at")
        _require_aware(self.ends_at, "ends_at")
        _require_aware(self.created_at, "created_at")
        if self.ends_at <= self.starts_at:
            raise DomainValidationError("ends_at must be later than starts_at")
        if self.destructive_actions_enabled and self.maximum_risk is not RiskLevel.L4:
            raise DomainValidationError(
                "destructive actions require the engagement maximum risk to be L4"
            )


@dataclass(frozen=True, slots=True)
class Flow:
    """A complete testing objective within an engagement."""

    engagement_id: EngagementId
    objective: str
    id: FlowId = field(default_factory=new_flow_id)
    created_at: datetime = field(default_factory=utc_now)

    def __post_init__(self) -> None:
        _require_text(self.objective, "objective")
        _require_aware(self.created_at, "created_at")


@dataclass(frozen=True, slots=True)
class Task:
    """A planned unit of work within a flow."""

    flow_id: FlowId
    title: str
    id: TaskId = field(default_factory=new_task_id)
    created_at: datetime = field(default_factory=utc_now)

    def __post_init__(self) -> None:
        _require_text(self.title, "title")
        _require_aware(self.created_at, "created_at")


@dataclass(frozen=True, slots=True)
class Action:
    """A concrete operation proposed by an agent or user."""

    engagement_id: EngagementId
    task_id: TaskId
    action_type: str
    normalized_target: str
    parameter_digest: str
    risk_level: RiskLevel
    idempotency_key: str
    id: ActionId = field(default_factory=new_action_id)
    state: ActionState = ActionState.PROPOSED
    approval_id: ApprovalId | None = None
    created_at: datetime = field(default_factory=utc_now)
    started_at: datetime | None = None
    completed_at: datetime | None = None

    def __post_init__(self) -> None:
        _require_text(self.action_type, "action_type")
        _require_text(self.normalized_target, "normalized_target")
        _require_text(self.idempotency_key, "idempotency_key")
        _require_sha256(self.parameter_digest, "parameter_digest")
        _require_aware(self.created_at, "created_at")
        if self.started_at is not None:
            _require_aware(self.started_at, "started_at")
        if self.completed_at is not None:
            _require_aware(self.completed_at, "completed_at")
        if self.started_at is not None and self.started_at < self.created_at:
            raise DomainValidationError("started_at must not be earlier than created_at")
        if self.completed_at is not None and self.completed_at < self.created_at:
            raise DomainValidationError("completed_at must not be earlier than created_at")
        if (
            self.started_at is not None
            and self.completed_at is not None
            and self.completed_at < self.started_at
        ):
            raise DomainValidationError("completed_at must not be earlier than started_at")


@dataclass(frozen=True, slots=True)
class WorkerExecution:
    """Durable, non-secret metadata for one disposable Worker lifecycle."""

    request_id: str
    engagement_id: EngagementId
    action_id: ActionId
    runtime_identity: str
    state: WorkerState
    created_at: datetime
    updated_at: datetime
    id: WorkerId = field(default_factory=new_worker_id)
    cleaned_up: bool = False
    error_code: str | None = None

    def __post_init__(self) -> None:
        _require_text(self.request_id, "request_id")
        _require_text(self.runtime_identity, "runtime_identity")
        _require_aware(self.created_at, "created_at")
        _require_aware(self.updated_at, "updated_at")
        if self.updated_at < self.created_at:
            raise DomainValidationError("updated_at must not be earlier than created_at")
        if self.cleaned_up and not self.state.terminal:
            raise DomainValidationError("cleaned_up requires a terminal Worker state")
        if self.error_code is not None:
            _require_text(self.error_code, "error_code")


@dataclass(frozen=True, slots=True)
class Approval:
    """Single-action approval bound to protected action properties."""

    engagement_id: EngagementId
    action_type: str
    normalized_target: str
    parameter_digest: str
    risk_level: RiskLevel
    expires_at: datetime
    permitted_executions: int
    approver: str
    id: ApprovalId = field(default_factory=new_approval_id)
    approved_at: datetime = field(default_factory=utc_now)
    consumed_executions: int = 0

    def __post_init__(self) -> None:
        _require_text(self.action_type, "action_type")
        _require_text(self.normalized_target, "normalized_target")
        _require_text(self.approver, "approver")
        _require_sha256(self.parameter_digest, "parameter_digest")
        _require_aware(self.expires_at, "expires_at")
        _require_aware(self.approved_at, "approved_at")
        if self.expires_at <= self.approved_at:
            raise DomainValidationError("expires_at must be later than approved_at")
        if self.permitted_executions < 1:
            raise DomainValidationError("permitted_executions must be at least one")
        if not 0 <= self.consumed_executions <= self.permitted_executions:
            raise DomainValidationError("consumed_executions is outside the permitted range")

    def authorizes(self, action: Action, *, at: datetime) -> bool:
        """Return whether this approval currently authorizes the exact action."""
        _require_aware(at, "at")
        return (
            self.approved_at <= at < self.expires_at
            and self.consumed_executions < self.permitted_executions
            and self.engagement_id == action.engagement_id
            and self.action_type == action.action_type
            and self.normalized_target == action.normalized_target
            and self.parameter_digest == action.parameter_digest
            and self.risk_level is action.risk_level
        )


@dataclass(frozen=True, slots=True)
class Evidence:
    """Immutable evidence metadata associated with an action."""

    action_id: ActionId
    tool_name: str
    tool_version: str
    digest: str
    previous_digest: str | None = None
    id: EvidenceId = field(default_factory=new_evidence_id)
    captured_at: datetime = field(default_factory=utc_now)

    def __post_init__(self) -> None:
        _require_text(self.tool_name, "tool_name")
        _require_text(self.tool_version, "tool_version")
        _require_sha256(self.digest, "digest")
        if self.previous_digest is not None:
            _require_sha256(self.previous_digest, "previous_digest")
        _require_aware(self.captured_at, "captured_at")


@dataclass(frozen=True, slots=True)
class Artifact:
    """A stored file or report derived from an action or evidence."""

    action_id: ActionId
    kind: ArtifactKind
    media_type: str
    storage_reference: str
    digest: str
    id: ArtifactId = field(default_factory=new_artifact_id)
    created_at: datetime = field(default_factory=utc_now)

    def __post_init__(self) -> None:
        _require_text(self.media_type, "media_type")
        _require_text(self.storage_reference, "storage_reference")
        _require_sha256(self.digest, "digest")
        _require_aware(self.created_at, "created_at")


@dataclass(frozen=True, slots=True)
class ReportExport:
    """Immutable, engagement-scoped report snapshot metadata."""

    engagement_id: EngagementId
    format: ReportFormat
    media_type: str
    digest: str
    size: int
    idempotency_key: str
    created_by: str
    id: ReportExportId = field(default_factory=new_report_export_id)
    created_at: datetime = field(default_factory=utc_now)

    def __post_init__(self) -> None:
        _require_text(self.media_type, "media_type")
        _require_sha256(self.digest, "digest")
        if self.size < 0:
            raise DomainValidationError("size must not be negative")
        _require_text(self.idempotency_key, "idempotency_key")
        _require_text(self.created_by, "created_by")
        _require_aware(self.created_at, "created_at")


@dataclass(frozen=True, slots=True)
class Finding:
    """A security finding whose verification is evidence-backed."""

    engagement_id: EngagementId
    title: str
    vulnerability_class: str
    affected_target: str
    evidence_ids: tuple[EvidenceId, ...] = ()
    status: FindingStatus = FindingStatus.CANDIDATE
    severity: FindingSeverity = FindingSeverity.INFORMATIONAL
    confidence: FindingConfidence = FindingConfidence.MEDIUM
    remediation: str = "Review the evidence and apply the relevant security control."
    id: FindingId = field(default_factory=new_finding_id)
    created_at: datetime = field(default_factory=utc_now)

    def __post_init__(self) -> None:
        _require_text(self.title, "title")
        _require_text(self.vulnerability_class, "vulnerability_class")
        _require_text(self.affected_target, "affected_target")
        _require_text(self.remediation, "remediation")
        _require_aware(self.created_at, "created_at")
        if self.status is FindingStatus.VERIFIED and not self.evidence_ids:
            raise DomainValidationError("verified findings require at least one evidence record")


@dataclass(frozen=True, slots=True)
class AuditEvent:
    """Immutable record of a security-relevant control-plane decision."""

    event_type: str
    actor: str
    payload: bytes
    engagement_id: EngagementId | None = None
    id: AuditEventId = field(default_factory=new_audit_event_id)
    created_at: datetime = field(default_factory=utc_now)

    def __post_init__(self) -> None:
        _require_text(self.event_type, "event_type")
        _require_text(self.actor, "actor")
        _require_aware(self.created_at, "created_at")
        object.__setattr__(self, "payload", bytes(self.payload))
