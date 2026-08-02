"""Transactional orchestration for one idempotent passive URL assessment."""

from __future__ import annotations

import json
from collections import deque
from dataclasses import dataclass
from datetime import UTC, datetime
from hashlib import sha256
from time import monotonic

from sqlalchemy import func, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from vuln_proof_claw.assessment.analyzer import analyze_passive_response
from vuln_proof_claw.assessment.discovery import (
    DISCOVERY_PRESETS,
    DiscoveredTarget,
    discover_targets,
)
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
from vuln_proof_claw.policy.scope import evaluate_scope

_ACTION_TYPE = "passive_fingerprint"
_DISCOVERY_ACTION_TYPE = "passive_discovery"


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
    pages_scanned: int = 0
    discovered_targets: tuple[DiscoveredTarget, ...] = ()
    crawl_truncated: bool = False


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
        filters = [ActionRecord.action_type == _ACTION_TYPE]
        if project_id is not None:
            filters.append(EngagementRecord.project_id == project_id)
        statement = (
            select(
                ActionRecord,
                EngagementRecord.project_id,
            )
            .join(EngagementRecord, EngagementRecord.id == ActionRecord.engagement_id)
            .where(*filters)
            .order_by(ActionRecord.created_at.desc(), ActionRecord.id.desc())
            .limit(limit)
            .offset(offset)
        )
        rows = self._session.execute(statement).all()
        engagement_ids = tuple({row[0].engagement_id for row in rows})
        evidence_counts: dict[str, int] = {}
        for engagement_id, count in self._session.execute(
                select(ActionRecord.engagement_id, func.count(EvidenceRecord.id))
                .join(EvidenceRecord, EvidenceRecord.action_id == ActionRecord.id)
                .where(
                    ActionRecord.engagement_id.in_(engagement_ids),
                    ActionRecord.action_type.in_((_ACTION_TYPE, _DISCOVERY_ACTION_TYPE)),
                )
                .group_by(ActionRecord.engagement_id)
        ).tuples():
            evidence_counts[engagement_id] = count  # noqa: PERF403 - SQLAlchemy typed row
        finding_counts: dict[str, int] = {}
        for engagement_id, count in self._session.execute(
                select(ActionRecord.engagement_id, func.count(func.distinct(FindingRecord.id)))
                .join(EvidenceRecord, EvidenceRecord.action_id == ActionRecord.id)
                .join(finding_evidence, finding_evidence.c.evidence_id == EvidenceRecord.id)
                .join(FindingRecord, FindingRecord.id == finding_evidence.c.finding_id)
                .where(
                    ActionRecord.engagement_id.in_(engagement_ids),
                    ActionRecord.action_type.in_((_ACTION_TYPE, _DISCOVERY_ACTION_TYPE)),
                )
                .group_by(ActionRecord.engagement_id)
        ).tuples():
            finding_counts[engagement_id] = count  # noqa: PERF403 - SQLAlchemy typed row
        error_codes = self._history_error_codes(
            tuple(row[0].id for row in rows),
            tuple({row[0].engagement_id for row in rows}),
        )
        items: list[PassiveAssessmentHistoryItem] = []
        for action, row_project_id in rows:
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
                    evidence_count=evidence_counts.get(action.engagement_id, 0),
                    findings_count=finding_counts.get(action.engagement_id, 0),
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
        action_type: str = _ACTION_TYPE,
        include_conventional: bool = False,
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
            if not self._matches(existing.entity, request, action_type):
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
                    action_type=action_type,
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
                if raced is None or not self._matches(raced.entity, request, action_type):
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
        return self._summary_by_id(
            action.id,
            replayed=existing is not None,
            discovered_targets=discover_targets(
                request.target,
                result.response,
                include_conventional=include_conventional,
            ),
        )

    def crawl(  # noqa: PLR0912, PLR0913 - explicit bounded crawl workflow
        self,
        engagement_id: EngagementId,
        root: PassiveAssessmentResult,
        idempotency_key: str,
        actor: str,
        transport: HttpCaptureTransport,
        *,
        limits: HttpCaptureLimits,
        user_agent: str,
        preset_name: str,
    ) -> PassiveAssessmentResult:
        """Follow discovered same-origin targets within fixed scope and budgets."""
        preset = DISCOVERY_PRESETS.get(preset_name)
        if preset is None:
            raise AssessmentError("discovery_preset_invalid")
        if root.state is not ActionState.SUCCEEDED or root.replayed:
            return self._summary_by_id(root.action_id, replayed=root.replayed)

        scope = ScopeRepository(self._session).get(engagement_id)
        if scope is None:
            raise AssessmentError("engagement_not_found")
        stored_root = ActionRepository(self._session).get(root.action_id)
        if stored_root is None:
            raise AssessmentError("assessment_not_found")
        deadline = monotonic() + preset.time_budget_seconds
        queue = deque(root.discovered_targets)
        seen = {
            stored_root.entity.normalized_target,
            *(item.url for item in root.discovered_targets),
        }
        scanned = 1
        requests = 1
        truncated = False

        while queue and scanned < preset.page_budget and requests < preset.request_budget:
            if monotonic() >= deadline:
                truncated = True
                break
            candidate = queue.popleft()
            if candidate.kind == "form":
                continue
            if candidate.kind == "asset" and not candidate.url.lower().endswith(
                (".js", ".mjs")
            ):
                continue
            decision = evaluate_scope(candidate.url, scope, at=datetime.now(UTC))
            if not decision.allowed:
                continue
            digest = sha256(candidate.url.encode()).hexdigest()[:24]
            child = self.run(
                engagement_id,
                candidate.url,
                f"{idempotency_key}:page:{digest}",
                actor,
                transport,
                limits=limits,
                user_agent=user_agent,
                action_type=_DISCOVERY_ACTION_TYPE,
            )
            requests += 1
            if child.state is not ActionState.SUCCEEDED:
                continue
            scanned += 1
            for discovered in child.discovered_targets:
                if discovered.url in seen:
                    continue
                seen.add(discovered.url)
                queue.append(discovered)

        if queue:
            truncated = True
        record_audit_event(
            self._session,
            engagement_id,
            "assessment.discovery_completed",
            actor,
            {
                "action_id": root.action_id,
                "pages_scanned": scanned,
                "preset": preset.name,
                "request_budget": preset.request_budget,
                "requests_used": requests,
                "targets_discovered": len(seen),
                "truncated": truncated,
            },
        )
        self._session.commit()
        return self._summary_by_id(
            root.action_id,
            replayed=False,
            pages_scanned=scanned,
            crawl_truncated=truncated,
        )

    def _create_action(  # noqa: PLR0913 - creation inputs are protected fields
        self,
        engagement_id: EngagementId,
        target: str,
        idempotency_key: str,
        actor: str,
        user_agent: str,
        *,
        action_type: str,
        at: datetime,
    ) -> Action:
        stored_engagement = EngagementRepository(self._session).get(engagement_id)
        scope = ScopeRepository(self._session).get(engagement_id)
        if stored_engagement is None or scope is None:
            raise AssessmentError("engagement_not_found")
        flow = Flow(
            engagement_id=engagement_id,
            objective=(
                "Bounded same-origin Web discovery"
                if action_type == _DISCOVERY_ACTION_TYPE
                else "Passive URL security assessment"
            ),
            created_at=at,
        )
        task = Task(
            flow_id=flow.id,
            title=(
                "Capture and analyze a discovered page"
                if action_type == _DISCOVERY_ACTION_TYPE
                else "Capture and analyze the target response"
            ),
            created_at=at,
        )
        action_id = new_action_id()
        request = self._request(action_id, target, user_agent)
        action = Action(
            id=action_id,
            engagement_id=engagement_id,
            task_id=task.id,
            action_type=action_type,
            normalized_target=request.target,
            parameter_digest=capture_parameter_digest(request),
            risk_level=classify_risk(action_type),
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
    def _matches(action: Action, request: HttpCaptureRequest, action_type: str) -> bool:
        return (
            action.action_type == action_type
            and action.normalized_target == request.target
            and action.parameter_digest == capture_parameter_digest(request)
        )

    def _summary_by_id(  # noqa: PLR0913, PLR0917 - explicit summary state
        self,
        action_id: ActionId,
        replayed: bool,
        error_code: str | None = None,
        discovered_targets: tuple[DiscoveredTarget, ...] = (),
        pages_scanned: int | None = None,
        crawl_truncated: bool = False,
    ) -> PassiveAssessmentResult:
        stored = ActionRepository(self._session).get(action_id)
        if stored is None:  # pragma: no cover - persistence invariant
            raise RuntimeError("assessment action disappeared")
        return self._summary(
            stored.entity,
            replayed=replayed,
            error_code=error_code,
            discovered_targets=discovered_targets,
            pages_scanned=pages_scanned,
            crawl_truncated=crawl_truncated,
        )

    def _summary(  # noqa: PLR0913 - explicit summary state
        self,
        action: Action,
        *,
        replayed: bool,
        error_code: str | None = None,
        discovered_targets: tuple[DiscoveredTarget, ...] = (),
        pages_scanned: int | None = None,
        crawl_truncated: bool = False,
    ) -> PassiveAssessmentResult:
        assessment_action_ids = tuple(
            ActionId(item)
            for item in self._session.scalars(
                select(ActionRecord.id).where(
                    ActionRecord.engagement_id == action.engagement_id,
                    ActionRecord.action_type.in_((_ACTION_TYPE, _DISCOVERY_ACTION_TYPE)),
                )
            )
        )
        evidence = tuple(
            item
            for assessment_action_id in assessment_action_ids
            for item in EvidenceRepository(self._session).for_action(assessment_action_id)
        )
        finding_ids = tuple(
            FindingId(item)
            for item in self._session.scalars(
                select(FindingRecord.id)
                .join(finding_evidence, finding_evidence.c.finding_id == FindingRecord.id)
                .join(
                    EvidenceRecord,
                    finding_evidence.c.evidence_id == EvidenceRecord.id,
                )
                .where(EvidenceRecord.action_id.in_(assessment_action_ids))
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
            pages_scanned=(
                pages_scanned
                if pages_scanned is not None
                else len({item.action_id for item in evidence})
            ),
            discovered_targets=discovered_targets,
            crawl_truncated=crawl_truncated,
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
