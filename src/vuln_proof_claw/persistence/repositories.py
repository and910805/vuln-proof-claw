"""Repositories translating between domain objects and SQLAlchemy records."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime

from sqlalchemy import delete, insert, select
from sqlalchemy.orm import Session

from vuln_proof_claw.domain.enums import ActionState, ArtifactKind, FindingStatus, RiskLevel
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
    TaskId,
)
from vuln_proof_claw.domain.models import (
    Action,
    Approval,
    Artifact,
    AuditEvent,
    Engagement,
    Evidence,
    Finding,
    Flow,
    Project,
    Task,
)
from vuln_proof_claw.persistence.models import (
    ActionRecord,
    ApprovalRecord,
    ArtifactRecord,
    AuditEventRecord,
    EngagementRecord,
    EngagementScopeRecord,
    EvidenceRecord,
    FindingRecord,
    FlowRecord,
    ProjectRecord,
    TaskRecord,
    finding_evidence,
)
from vuln_proof_claw.policy.scope import EngagementScope


class PersistenceError(Exception):
    """Base class for expected persistence failures."""


class ConcurrentUpdateError(PersistenceError):
    """Raised when an optimistic version no longer matches."""


@dataclass(frozen=True, slots=True)
class Stored[T]:
    """A domain entity paired with its persistence version."""

    entity: T
    version: int


def _utc(value: datetime) -> datetime:
    """Restore UTC awareness for dialects that return naive timestamps."""
    if value.tzinfo is None:
        return value.replace(tzinfo=UTC)
    return value.astimezone(UTC)


class ProjectRepository:
    def __init__(self, session: Session) -> None:
        self._session = session

    def add(self, project: Project) -> None:
        self._session.add(
            ProjectRecord(id=project.id, name=project.name, created_at=project.created_at)
        )
        self._session.flush()

    def get(self, project_id: ProjectId) -> Project | None:
        row = self._session.get(ProjectRecord, project_id)
        if row is None:
            return None
        return Project(id=ProjectId(row.id), name=row.name, created_at=_utc(row.created_at))

    def list(self, *, limit: int = 100, offset: int = 0) -> tuple[Project, ...]:
        rows = self._session.scalars(
            select(ProjectRecord)
            .order_by(ProjectRecord.created_at.desc(), ProjectRecord.id.desc())
            .limit(limit)
            .offset(offset)
        )
        return tuple(
            Project(id=ProjectId(row.id), name=row.name, created_at=_utc(row.created_at))
            for row in rows
        )


class EngagementRepository:
    def __init__(self, session: Session) -> None:
        self._session = session

    def add(self, engagement: Engagement) -> None:
        self._session.add(
            EngagementRecord(
                id=engagement.id,
                project_id=engagement.project_id,
                name=engagement.name,
                starts_at=engagement.starts_at,
                ends_at=engagement.ends_at,
                maximum_risk=engagement.maximum_risk.value,
                destructive_actions_enabled=engagement.destructive_actions_enabled,
                created_at=engagement.created_at,
            )
        )
        self._session.flush()

    def get(self, engagement_id: EngagementId) -> Stored[Engagement] | None:
        row = self._session.get(EngagementRecord, engagement_id)
        if row is None:
            return None
        return Stored(
            Engagement(
                id=EngagementId(row.id),
                project_id=ProjectId(row.project_id),
                name=row.name,
                starts_at=_utc(row.starts_at),
                ends_at=_utc(row.ends_at),
                maximum_risk=RiskLevel(row.maximum_risk),
                destructive_actions_enabled=row.destructive_actions_enabled,
                created_at=_utc(row.created_at),
            ),
            row.version,
        )

    def list_for_project(
        self,
        project_id: ProjectId,
        *,
        limit: int = 100,
        offset: int = 0,
    ) -> tuple[Stored[Engagement], ...]:
        rows = self._session.scalars(
            select(EngagementRecord)
            .where(EngagementRecord.project_id == project_id)
            .order_by(EngagementRecord.created_at.desc(), EngagementRecord.id.desc())
            .limit(limit)
            .offset(offset)
        )
        return tuple(Stored(self._domain_from_record(row), row.version) for row in rows)

    @staticmethod
    def _domain_from_record(row: EngagementRecord) -> Engagement:
        return Engagement(
            id=EngagementId(row.id),
            project_id=ProjectId(row.project_id),
            name=row.name,
            starts_at=_utc(row.starts_at),
            ends_at=_utc(row.ends_at),
            maximum_risk=RiskLevel(row.maximum_risk),
            destructive_actions_enabled=row.destructive_actions_enabled,
            created_at=_utc(row.created_at),
        )


class ScopeRepository:
    """Persist normalized engagement scope rules as one atomic policy document."""

    def __init__(self, session: Session) -> None:
        self._session = session

    def add(self, engagement_id: EngagementId, scope: EngagementScope) -> None:
        self._session.add(
            EngagementScopeRecord(
                engagement_id=engagement_id,
                allowed_hostnames=sorted(scope.allowed_hostnames),
                allowed_cidrs=[str(network) for network in scope.allowed_networks],
                allowed_ports=sorted(scope.allowed_ports),
                allowed_schemes=sorted(scope.allowed_schemes),
                allowed_paths=list(scope.allowed_paths),
                denied_hostnames=sorted(scope.denied_hostnames),
                denied_cidrs=[str(network) for network in scope.denied_networks],
                denied_paths=list(scope.denied_paths),
                valid_from=scope.valid_from,
                valid_until=scope.valid_until,
            )
        )
        self._session.flush()

    def get(self, engagement_id: EngagementId) -> EngagementScope | None:
        row = self._session.get(EngagementScopeRecord, engagement_id)
        if row is None:
            return None
        return EngagementScope.create(
            allowed_hostnames=tuple(row.allowed_hostnames),
            allowed_cidrs=tuple(row.allowed_cidrs),
            allowed_ports=tuple(row.allowed_ports),
            allowed_schemes=tuple(row.allowed_schemes),
            allowed_paths=tuple(row.allowed_paths),
            denied_hostnames=tuple(row.denied_hostnames),
            denied_cidrs=tuple(row.denied_cidrs),
            denied_paths=tuple(row.denied_paths),
            valid_from=_utc(row.valid_from) if row.valid_from else None,
            valid_until=_utc(row.valid_until) if row.valid_until else None,
        )


class FlowRepository:
    def __init__(self, session: Session) -> None:
        self._session = session

    def add(self, flow: Flow) -> None:
        self._session.add(
            FlowRecord(
                id=flow.id,
                engagement_id=flow.engagement_id,
                objective=flow.objective,
                created_at=flow.created_at,
            )
        )
        self._session.flush()

    def get(self, flow_id: FlowId) -> Stored[Flow] | None:
        row = self._session.get(FlowRecord, flow_id)
        if row is None:
            return None
        return Stored(
            Flow(
                id=FlowId(row.id),
                engagement_id=EngagementId(row.engagement_id),
                objective=row.objective,
                created_at=_utc(row.created_at),
            ),
            row.version,
        )

    def list_for_engagement(
        self,
        engagement_id: EngagementId,
        *,
        limit: int = 100,
        offset: int = 0,
    ) -> tuple[Stored[Flow], ...]:
        rows = self._session.scalars(
            select(FlowRecord)
            .where(FlowRecord.engagement_id == engagement_id)
            .order_by(FlowRecord.created_at.desc(), FlowRecord.id.desc())
            .limit(limit)
            .offset(offset)
        )
        return tuple(
            Stored(
                Flow(
                    id=FlowId(row.id),
                    engagement_id=EngagementId(row.engagement_id),
                    objective=row.objective,
                    created_at=_utc(row.created_at),
                ),
                row.version,
            )
            for row in rows
        )


class TaskRepository:
    def __init__(self, session: Session) -> None:
        self._session = session

    def add(self, task: Task) -> None:
        self._session.add(
            TaskRecord(
                id=task.id,
                flow_id=task.flow_id,
                title=task.title,
                created_at=task.created_at,
            )
        )
        self._session.flush()

    def get(self, task_id: TaskId) -> Task | None:
        row = self._session.get(TaskRecord, task_id)
        if row is None:
            return None
        return Task(
            id=TaskId(row.id),
            flow_id=FlowId(row.flow_id),
            title=row.title,
            created_at=_utc(row.created_at),
        )

    def list_for_flow(
        self,
        flow_id: FlowId,
        *,
        limit: int = 100,
        offset: int = 0,
    ) -> tuple[Task, ...]:
        rows = self._session.scalars(
            select(TaskRecord)
            .where(TaskRecord.flow_id == flow_id)
            .order_by(TaskRecord.created_at.desc(), TaskRecord.id.desc())
            .limit(limit)
            .offset(offset)
        )
        return tuple(
            Task(
                id=TaskId(row.id),
                flow_id=FlowId(row.flow_id),
                title=row.title,
                created_at=_utc(row.created_at),
            )
            for row in rows
        )


class ApprovalRepository:
    def __init__(self, session: Session) -> None:
        self._session = session

    def add(self, approval: Approval) -> None:
        self._session.add(
            ApprovalRecord(
                id=approval.id,
                engagement_id=approval.engagement_id,
                action_type=approval.action_type,
                normalized_target=approval.normalized_target,
                parameter_digest=approval.parameter_digest,
                risk_level=approval.risk_level.value,
                expires_at=approval.expires_at,
                permitted_executions=approval.permitted_executions,
                approver=approval.approver,
                approved_at=approval.approved_at,
                consumed_executions=approval.consumed_executions,
            )
        )
        self._session.flush()

    def get(self, approval_id: ApprovalId) -> Stored[Approval] | None:
        row = self._session.get(ApprovalRecord, approval_id)
        if row is None:
            return None
        return Stored(self._domain_from_record(row), row.version)

    def save(self, approval: Approval, *, expected_version: int) -> Stored[Approval]:
        """Persist approval consumption with optimistic concurrency control."""
        row = self._session.scalar(
            select(ApprovalRecord).where(
                ApprovalRecord.id == approval.id,
                ApprovalRecord.version == expected_version,
            )
        )
        if row is None:
            raise ConcurrentUpdateError
        row.consumed_executions = approval.consumed_executions
        self._session.flush()
        return Stored(self._domain_from_record(row), row.version)

    @staticmethod
    def _domain_from_record(row: ApprovalRecord) -> Approval:
        return Approval(
            id=ApprovalId(row.id),
            engagement_id=EngagementId(row.engagement_id),
            action_type=row.action_type,
            normalized_target=row.normalized_target,
            parameter_digest=row.parameter_digest,
            risk_level=RiskLevel(row.risk_level),
            expires_at=_utc(row.expires_at),
            permitted_executions=row.permitted_executions,
            approver=row.approver,
            approved_at=_utc(row.approved_at),
            consumed_executions=row.consumed_executions,
        )


class ActionRepository:
    def __init__(self, session: Session) -> None:
        self._session = session

    def add(self, action: Action) -> None:
        self._session.add(self._record_from_domain(action))
        self._session.flush()

    def get(self, action_id: ActionId) -> Stored[Action] | None:
        row = self._session.get(ActionRecord, action_id)
        if row is None:
            return None
        return Stored(self._domain_from_record(row), row.version)

    def get_by_idempotency_key(
        self,
        engagement_id: EngagementId,
        idempotency_key: str,
    ) -> Stored[Action] | None:
        row = self._session.scalar(
            select(ActionRecord).where(
                ActionRecord.engagement_id == engagement_id,
                ActionRecord.idempotency_key == idempotency_key,
            )
        )
        if row is None:
            return None
        return Stored(self._domain_from_record(row), row.version)

    def list_for_engagement(
        self,
        engagement_id: EngagementId,
        *,
        limit: int = 100,
        offset: int = 0,
    ) -> tuple[Stored[Action], ...]:
        rows = self._session.scalars(
            select(ActionRecord)
            .where(ActionRecord.engagement_id == engagement_id)
            .order_by(ActionRecord.created_at.desc(), ActionRecord.id.desc())
            .limit(limit)
            .offset(offset)
        )
        return tuple(Stored(self._domain_from_record(row), row.version) for row in rows)

    def save(self, action: Action, *, expected_version: int) -> Stored[Action]:
        row = self._session.scalar(
            select(ActionRecord).where(
                ActionRecord.id == action.id,
                ActionRecord.version == expected_version,
            )
        )
        if row is None:
            raise ConcurrentUpdateError

        row.state = action.state.value
        row.approval_id = action.approval_id
        row.started_at = action.started_at
        row.completed_at = action.completed_at
        self._session.flush()
        return Stored(self._domain_from_record(row), row.version)

    @staticmethod
    def _record_from_domain(action: Action) -> ActionRecord:
        return ActionRecord(
            id=action.id,
            engagement_id=action.engagement_id,
            task_id=action.task_id,
            action_type=action.action_type,
            normalized_target=action.normalized_target,
            parameter_digest=action.parameter_digest,
            risk_level=action.risk_level.value,
            idempotency_key=action.idempotency_key,
            state=action.state.value,
            approval_id=action.approval_id,
            created_at=action.created_at,
            started_at=action.started_at,
            completed_at=action.completed_at,
        )

    @staticmethod
    def _domain_from_record(row: ActionRecord) -> Action:
        return Action(
            id=ActionId(row.id),
            engagement_id=EngagementId(row.engagement_id),
            task_id=TaskId(row.task_id),
            action_type=row.action_type,
            normalized_target=row.normalized_target,
            parameter_digest=row.parameter_digest,
            risk_level=RiskLevel(row.risk_level),
            idempotency_key=row.idempotency_key,
            state=ActionState(row.state),
            approval_id=ApprovalId(row.approval_id) if row.approval_id else None,
            created_at=_utc(row.created_at),
            started_at=_utc(row.started_at) if row.started_at else None,
            completed_at=_utc(row.completed_at) if row.completed_at else None,
        )


class EvidenceRepository:
    def __init__(self, session: Session) -> None:
        self._session = session

    def add(self, evidence: Evidence) -> None:
        self._session.add(
            EvidenceRecord(
                id=evidence.id,
                action_id=evidence.action_id,
                tool_name=evidence.tool_name,
                tool_version=evidence.tool_version,
                digest=evidence.digest,
                previous_digest=evidence.previous_digest,
                captured_at=evidence.captured_at,
            )
        )
        self._session.flush()

    def get(self, evidence_id: EvidenceId) -> Evidence | None:
        row = self._session.get(EvidenceRecord, evidence_id)
        if row is None:
            return None
        return self._domain_from_record(row)

    def for_action(self, action_id: ActionId) -> tuple[Evidence, ...]:
        rows = self._session.scalars(
            select(EvidenceRecord)
            .where(EvidenceRecord.action_id == action_id)
            .order_by(EvidenceRecord.captured_at, EvidenceRecord.id)
        )
        return tuple(self._domain_from_record(row) for row in rows)

    @staticmethod
    def _domain_from_record(row: EvidenceRecord) -> Evidence:
        return Evidence(
            id=EvidenceId(row.id),
            action_id=ActionId(row.action_id),
            tool_name=row.tool_name,
            tool_version=row.tool_version,
            digest=row.digest,
            previous_digest=row.previous_digest,
            captured_at=_utc(row.captured_at),
        )


class ArtifactRepository:
    def __init__(self, session: Session) -> None:
        self._session = session

    def add(self, artifact: Artifact) -> None:
        self._session.add(
            ArtifactRecord(
                id=artifact.id,
                action_id=artifact.action_id,
                kind=artifact.kind.value,
                media_type=artifact.media_type,
                storage_reference=artifact.storage_reference,
                digest=artifact.digest,
                created_at=artifact.created_at,
            )
        )
        self._session.flush()

    def get(self, artifact_id: ArtifactId) -> Artifact | None:
        row = self._session.get(ArtifactRecord, artifact_id)
        if row is None:
            return None
        return Artifact(
            id=ArtifactId(row.id),
            action_id=ActionId(row.action_id),
            kind=ArtifactKind(row.kind),
            media_type=row.media_type,
            storage_reference=row.storage_reference,
            digest=row.digest,
            created_at=_utc(row.created_at),
        )


class FindingRepository:
    def __init__(self, session: Session) -> None:
        self._session = session

    def add(self, finding: Finding) -> None:
        self._session.add(
            FindingRecord(
                id=finding.id,
                engagement_id=finding.engagement_id,
                title=finding.title,
                vulnerability_class=finding.vulnerability_class,
                affected_target=finding.affected_target,
                status=finding.status.value,
                created_at=finding.created_at,
            )
        )
        self._session.flush()
        if finding.evidence_ids:
            self._session.execute(
                insert(finding_evidence),
                [
                    {"finding_id": finding.id, "evidence_id": evidence_id}
                    for evidence_id in finding.evidence_ids
                ],
            )

    def get(self, finding_id: FindingId) -> Stored[Finding] | None:
        row = self._session.get(FindingRecord, finding_id)
        if row is None:
            return None
        evidence_ids = tuple(
            EvidenceId(value)
            for value in self._session.scalars(
                select(finding_evidence.c.evidence_id).where(
                    finding_evidence.c.finding_id == finding_id
                )
            )
        )
        return Stored(
            Finding(
                id=FindingId(row.id),
                engagement_id=EngagementId(row.engagement_id),
                title=row.title,
                vulnerability_class=row.vulnerability_class,
                affected_target=row.affected_target,
                evidence_ids=evidence_ids,
                status=FindingStatus(row.status),
                created_at=_utc(row.created_at),
            ),
            row.version,
        )

    def replace_evidence(self, finding_id: FindingId, evidence_ids: tuple[EvidenceId, ...]) -> None:
        self._session.execute(
            delete(finding_evidence).where(finding_evidence.c.finding_id == finding_id)
        )
        if evidence_ids:
            self._session.execute(
                insert(finding_evidence),
                [
                    {"finding_id": finding_id, "evidence_id": evidence_id}
                    for evidence_id in evidence_ids
                ],
            )


class AuditEventRepository:
    """Append and inspect immutable engagement audit events."""

    def __init__(self, session: Session) -> None:
        self._session = session

    def add(self, event: AuditEvent) -> None:
        self._session.add(
            AuditEventRecord(
                id=event.id,
                engagement_id=event.engagement_id,
                event_type=event.event_type,
                actor=event.actor,
                payload=event.payload,
                created_at=event.created_at,
            )
        )
        self._session.flush()

    def list_for_engagement(
        self,
        engagement_id: EngagementId,
        *,
        limit: int = 100,
        offset: int = 0,
    ) -> tuple[AuditEvent, ...]:
        rows = self._session.scalars(
            select(AuditEventRecord)
            .where(AuditEventRecord.engagement_id == engagement_id)
            .order_by(AuditEventRecord.created_at.desc(), AuditEventRecord.id.desc())
            .limit(limit)
            .offset(offset)
        )
        return tuple(
            AuditEvent(
                id=AuditEventId(row.id),
                engagement_id=EngagementId(row.engagement_id) if row.engagement_id else None,
                event_type=row.event_type,
                actor=row.actor,
                payload=row.payload,
                created_at=_utc(row.created_at),
            )
            for row in rows
        )
