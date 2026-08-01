"""Transactional orchestration for one idempotent passive URL assessment."""

from __future__ import annotations

import json
from dataclasses import dataclass
from datetime import UTC, datetime

from sqlalchemy import func, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from vuln_proof_claw.assessment.analyzer import analyze_passive_response
from vuln_proof_claw.audit import record_audit_event
from vuln_proof_claw.domain.action_state import transition_action
from vuln_proof_claw.domain.enums import ActionState
from vuln_proof_claw.domain.identifiers import (
    ActionId,
    EngagementId,
    EvidenceId,
    FindingId,
    ProjectId,
    new_action_id,
)
from vuln_proof_claw.domain.models import Action, Flow, Task
from vuln_proof_claw.execution.http_capture import (
    HttpCaptureCoordinator,
    HttpCaptureLimits,
    HttpCaptureRequest,
    HttpCaptureTransport,
    capture_parameter_digest,
)
from vuln_proof_claw.persistence.models import (
    ActionRecord,
    AuditEventRecord,
    EngagementRecord,
    EvidenceRecord,
    FindingRecord,
    finding_evidence,
)
from vuln_proof_claw.persistence.repositories import (
    ActionRepository,
    EngagementRepository,
    EvidenceRepository,
    FindingRepository,
    FlowRepository,
    ScopeRepository,
    TaskRepository,
)
from vuln_proof_claw.policy.decision import DecisionKind, PolicyConfig, decide_action
from vuln_proof_claw.policy.risk import classify_risk

_ACTION_TYPE = "passive_fingerprint"


class AssessmentError(Exception):
    """Stable application-level assessment failure."""


class AssessmentConflictError(AssessmentError):
    """Raised when an idempotency key is reused for different protected input."""


@dataclass(frozen=True, slots=True)
class PassiveAssessmentResult:
    action_id: ActionId
    engagement_id: EngagementId
    state: ActionState
    evidence_ids: tuple[EvidenceId, ...]
    finding_ids: tuple[FindingId, ...]
    error_code: str | None
    replayed: bool


@dataclass(frozen=True, slots=True)
class PassiveAssessmentHistoryItem:
    action_id: ActionId
    engagement_id: EngagementId
    project_id: ProjectId
    target: str
    state: ActionState
    created_at: datetime
    completed_at: datetime | None
    evidence_count: int
    findings_count: int
    error_code: str | None


@dataclass(frozen=True, slots=True)
class PassiveAssessmentHistoryPage:
    items: tuple[PassiveAssessmentHistoryItem, ...]
    total: int


class PassiveAssessmentService:
    """Create, execute, analyze, and audit one passive HTTP capture."""

    def __init__(self, session: Session) -> None:
        self._session = session

    def get(
        self, engagement_id: EngagementId, action_id: ActionId
    ) -> PassiveAssessmentResult:
        """Return a persisted assessment without initiating network activity."""
        stored = ActionRepository(self._session).get(action_id)
        if (
            stored is None
            or stored.entity.engagement_id != engagement_id
            or stored.entity.action_type != _ACTION_TYPE
        ):
            raise AssessmentError("assessment_not_found")
        return self._summary(stored.entity, replayed=True)

    def list_history(
        self,
        *,
        project_id: ProjectId | None = None,
        limit: int = 50,
        offset: int = 0,
    ) -> PassiveAssessmentHistoryPage:
        """List persisted passive assessments without contacting any target."""
        evidence_count = (
            select(func.count(EvidenceRecord.id))
            .where(EvidenceRecord.action_id == ActionRecord.id)
            .correlate(ActionRecord)
            .scalar_subquery()
        )
        finding_count = (
            select(func.count(func.distinct(FindingRecord.id)))
            .select_from(FindingRecord)
            .join(finding_evidence, finding_evidence.c.finding_id == FindingRecord.id)
            .join(EvidenceRecord, finding_evidence.c.evidence_id == EvidenceRecord.id)
            .where(EvidenceRecord.action_id == ActionRecord.id)
            .correlate(ActionRecord)
            .scalar_subquery()
        )
        filters = [ActionRecord.action_type == _ACTION_TYPE]
        if project_id is not None:
            filters.append(EngagementRecord.project_id == project_id)
        statement = (
            select(
                ActionRecord,
                EngagementRecord.project_id,
                evidence_count.label("evidence_count"),
                finding_count.label("finding_count"),
            )
            .join(EngagementRecord, EngagementRecord.id == ActionRecord.engagement_id)
            .where(*filters)
            .order_by(ActionRecord.created_at.desc(), ActionRecord.id.desc())
            .limit(limit)
            .offset(offset)
        )
        rows = self._session.execute(statement).all()
        error_codes = self._history_error_codes(
            tuple(row[0].id for row in rows),
            tuple({row[0].engagement_id for row in rows}),
        )
        items: list[PassiveAssessmentHistoryItem] = []
        for action, row_project_id, row_evidence_count, row_finding_count in rows:
            items.append(
                PassiveAssessmentHistoryItem(
                    action_id=ActionId(action.id),
                    engagement_id=EngagementId(action.engagement_id),
                    project_id=ProjectId(row_project_id),
                    target=action.normalized_target,
                    state=ActionState(action.state),
                    created_at=self._utc(action.created_at),
                    completed_at=(
                        self._utc(action.completed_at) if action.completed_at else None
                    ),
                    evidence_count=row_evidence_count,
                    findings_count=row_finding_count,
                    error_code=error_codes.get(action.id),
                )
            )
        total = self._session.scalar(
            select(func.count())
            .select_from(ActionRecord)
            .join(EngagementRecord, EngagementRecord.id == ActionRecord.engagement_id)
            .where(*filters)
        ) or 0
        return PassiveAssessmentHistoryPage(items=tuple(items), total=total)

    def _history_error_codes(
        self,
        action_ids: tuple[str, ...],
        engagement_ids: tuple[str, ...],
    ) -> dict[str, str]:
        """Read failure codes for one history page in a single audit query."""
        if not action_ids:
            return {}
        action_id_set = set(action_ids)
        events = self._session.scalars(
            select(AuditEventRecord)
            .where(
                AuditEventRecord.event_type == "assessment.failed",
                AuditEventRecord.engagement_id.in_(engagement_ids),
            )
            .order_by(AuditEventRecord.created_at.desc(), AuditEventRecord.id.desc())
        )
        result: dict[str, str] = {}
        for event in events:
            try:
                payload = json.loads(event.payload)
            except (json.JSONDecodeError, UnicodeDecodeError, TypeError):
                continue
            action_id = payload.get("action_id")
            error_code = payload.get("error_code")
            if (
                isinstance(action_id, str)
                and action_id in action_id_set
                and action_id not in result
                and isinstance(error_code, str)
            ):
                result[action_id] = error_code
        return result

    @staticmethod
    def _utc(value: datetime) -> datetime:
        if value.tzinfo is None:
            return value.replace(tzinfo=UTC)
        return value.astimezone(UTC)

    def run(  # noqa: PLR0913 - explicit security inputs remain visible
        self,
        engagement_id: EngagementId,
        target: str,
        idempotency_key: str,
        actor: str,
        transport: HttpCaptureTransport,
        *,
        limits: HttpCaptureLimits,
        user_agent: str,
    ) -> PassiveAssessmentResult:
        engagement = EngagementRepository(self._session).get(engagement_id)
        scope = ScopeRepository(self._session).get(engagement_id)
        if engagement is None or scope is None:
            raise AssessmentError("engagement_not_found")

        protected_key = f"assessment:{idempotency_key}"
        existing = ActionRepository(self._session).get_by_idempotency_key(
            engagement_id, protected_key
        )
        if existing is not None:
            request = self._request(existing.entity.id, target, user_agent)
            if not self._matches(existing.entity, request):
                raise AssessmentConflictError("idempotency_key_conflict")
            if existing.entity.state is not ActionState.QUEUED:
                return self._summary(existing.entity, replayed=True)
            action = existing.entity
        else:
            try:
                action = self._create_action(
                    engagement_id,
                    target,
                    protected_key,
                    actor,
                    user_agent,
                    at=datetime.now(UTC),
                )
            except IntegrityError as error:
                self._session.rollback()
                raced = ActionRepository(self._session).get_by_idempotency_key(
                    engagement_id, protected_key
                )
                request = self._request(
                    raced.entity.id if raced is not None else new_action_id(),
                    target,
                    user_agent,
                )
                if raced is None or not self._matches(raced.entity, request):
                    raise AssessmentConflictError("assessment_persistence_conflict") from error
                existing = raced
                action = raced.entity
            if action.state is not ActionState.QUEUED:
                return self._summary(action, replayed=existing is not None)

        request = self._request(action.id, target, user_agent)
        result = HttpCaptureCoordinator(self._session, transport).capture(
            request,
            limits=limits,
        )
        if result.evidence is None or result.response is None:
            record_audit_event(
                self._session,
                engagement_id,
                "assessment.failed",
                actor,
                {"action_id": action.id, "error_code": result.error_code},
            )
            self._session.commit()
            return self._summary_by_id(
                action.id,
                replayed=existing is not None,
                error_code=result.error_code,
            )

        evidence_id = result.evidence.metadata.evidence_id
        findings = analyze_passive_response(
            engagement_id,
            request.target,
            evidence_id,
            result.response,
        )
        repository = FindingRepository(self._session)
        for finding in findings:
            repository.add(finding)
        record_audit_event(
            self._session,
            engagement_id,
            "assessment.completed",
            actor,
            {
                "action_id": action.id,
                "evidence_id": evidence_id,
                "finding_count": len(findings),
                "status_code": result.response.status_code,
            },
        )
        self._session.commit()
        return self._summary_by_id(action.id, replayed=existing is not None)

    def _create_action(  # noqa: PLR0913 - creation inputs are protected fields
        self,
        engagement_id: EngagementId,
        target: str,
        idempotency_key: str,
        actor: str,
        user_agent: str,
        *,
        at: datetime,
    ) -> Action:
        stored_engagement = EngagementRepository(self._session).get(engagement_id)
        scope = ScopeRepository(self._session).get(engagement_id)
        if stored_engagement is None or scope is None:
            raise AssessmentError("engagement_not_found")
        flow = Flow(
            engagement_id=engagement_id,
            objective="Passive URL security assessment",
            created_at=at,
        )
        task = Task(
            flow_id=flow.id,
            title="Capture and analyze the target response",
            created_at=at,
        )
        action_id = new_action_id()
        request = self._request(action_id, target, user_agent)
        action = Action(
            id=action_id,
            engagement_id=engagement_id,
            task_id=task.id,
            action_type=_ACTION_TYPE,
            normalized_target=request.target,
            parameter_digest=capture_parameter_digest(request),
            risk_level=classify_risk(_ACTION_TYPE),
            idempotency_key=idempotency_key,
            created_at=at,
        )
        FlowRepository(self._session).add(flow)
        TaskRepository(self._session).add(task)
        actions = ActionRepository(self._session)
        actions.add(action)
        stored = actions.get(action.id)
        if stored is None:  # pragma: no cover - flush/get invariant
            raise RuntimeError("persisted assessment action could not be reloaded")
        checking = transition_action(action, ActionState.POLICY_CHECK, at=at)
        stored_checking = actions.save(checking, expected_version=stored.version)
        engagement = stored_engagement.entity
        decision = decide_action(
            checking,
            scope=scope,
            config=PolicyConfig(
                maximum_risk=engagement.maximum_risk,
                destructive_actions_enabled=engagement.destructive_actions_enabled,
            ),
            at=at,
        )
        target_state = (
            ActionState.QUEUED if decision.kind is DecisionKind.ALLOW else ActionState.DENIED
        )
        evaluated = transition_action(stored_checking.entity, target_state, at=at)
        saved = actions.save(evaluated, expected_version=stored_checking.version)
        record_audit_event(
            self._session,
            engagement_id,
            "assessment.created",
            actor,
            {
                "action_id": action.id,
                "decision": decision.kind,
                "reason": decision.reason,
                "target": request.target,
            },
            at=at,
        )
        self._session.commit()
        return saved.entity

    @staticmethod
    def _request(action_id: ActionId, target: str, user_agent: str) -> HttpCaptureRequest:
        return HttpCaptureRequest(
            action_id=action_id,
            method="GET",
            target=target,
            headers=(
                ("Accept", "text/html,application/xhtml+xml,application/json"),
                ("User-Agent", user_agent),
            ),
        )

    @staticmethod
    def _matches(action: Action, request: HttpCaptureRequest) -> bool:
        return (
            action.action_type == _ACTION_TYPE
            and action.normalized_target == request.target
            and action.parameter_digest == capture_parameter_digest(request)
        )

    def _summary_by_id(
        self,
        action_id: ActionId,
        replayed: bool,
        error_code: str | None = None,
    ) -> PassiveAssessmentResult:
        stored = ActionRepository(self._session).get(action_id)
        if stored is None:  # pragma: no cover - persistence invariant
            raise RuntimeError("assessment action disappeared")
        return self._summary(stored.entity, replayed=replayed, error_code=error_code)

    def _summary(
        self,
        action: Action,
        *,
        replayed: bool,
        error_code: str | None = None,
    ) -> PassiveAssessmentResult:
        evidence = EvidenceRepository(self._session).for_action(action.id)
        finding_ids = tuple(
            FindingId(item)
            for item in self._session.scalars(
                select(FindingRecord.id)
                .join(finding_evidence, finding_evidence.c.finding_id == FindingRecord.id)
                .join(
                    EvidenceRecord,
                    finding_evidence.c.evidence_id == EvidenceRecord.id,
                )
                .where(EvidenceRecord.action_id == action.id)
                .order_by(FindingRecord.created_at, FindingRecord.id)
            )
        )
        persisted_error = error_code or self._persisted_error_code(action)
        return PassiveAssessmentResult(
            action_id=action.id,
            engagement_id=action.engagement_id,
            state=action.state,
            evidence_ids=tuple(item.id for item in evidence),
            finding_ids=finding_ids,
            error_code=persisted_error,
            replayed=replayed,
        )

    def _persisted_error_code(self, action: Action) -> str | None:
        """Recover a safe terminal error from the immutable audit trail."""
        if action.state is not ActionState.FAILED:
            return None
        events = self._session.scalars(
            select(AuditEventRecord)
            .where(
                AuditEventRecord.engagement_id == action.engagement_id,
                AuditEventRecord.event_type == "assessment.failed",
            )
            .order_by(AuditEventRecord.created_at.desc(), AuditEventRecord.id.desc())
        )
        for event in events:
            try:
                payload = json.loads(event.payload)
            except (json.JSONDecodeError, UnicodeDecodeError, TypeError):
                continue
            if payload.get("action_id") != action.id:
                continue
            value = payload.get("error_code")
            return value if isinstance(value, str) else None
        return None
