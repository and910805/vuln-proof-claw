"""Flow, task, action proposal, and audit endpoints."""

from __future__ import annotations

import json
from datetime import UTC, datetime
from typing import Annotated, Any

from fastapi import APIRouter, Depends, HTTPException, Query, Response, status
from sqlalchemy import func, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from vuln_proof_claw.api.dependencies import get_session
from vuln_proof_claw.api.schemas.workflow import (
    ActionListResponse,
    ActionSummary,
    AuditEventListResponse,
    AuditEventSummary,
    FlowCreate,
    FlowListResponse,
    FlowSummary,
    HttpActionCreate,
    TaskCreate,
    TaskListResponse,
    TaskSummary,
)
from vuln_proof_claw.domain.action_state import transition_action
from vuln_proof_claw.domain.enums import ActionState
from vuln_proof_claw.domain.errors import DomainValidationError
from vuln_proof_claw.domain.identifiers import (
    ActionId,
    EngagementId,
    FlowId,
    TaskId,
    new_action_id,
)
from vuln_proof_claw.domain.models import Action, AuditEvent, Flow, Task
from vuln_proof_claw.evidence.canonical import canonical_json
from vuln_proof_claw.execution.http_capture import HttpCaptureRequest, capture_parameter_digest
from vuln_proof_claw.persistence.models import (
    ActionRecord,
    AuditEventRecord,
    FlowRecord,
    TaskRecord,
)
from vuln_proof_claw.persistence.repositories import (
    ActionRepository,
    AuditEventRepository,
    EngagementRepository,
    FlowRepository,
    ScopeRepository,
    TaskRepository,
)
from vuln_proof_claw.policy.decision import (
    DecisionKind,
    PolicyConfig,
    PolicyDecision,
    decide_action,
)
from vuln_proof_claw.policy.risk import classify_risk, normalize_action_type

router = APIRouter(tags=["workflow"])
SessionDependency = Annotated[Session, Depends(get_session)]
_AUDIT_ACTOR = "api:unauthenticated"


def _flow_summary(flow: Flow) -> FlowSummary:
    return FlowSummary(
        id=flow.id,
        engagement_id=flow.engagement_id,
        objective=flow.objective,
        created_at=flow.created_at,
    )


def _task_summary(task: Task) -> TaskSummary:
    return TaskSummary(
        id=task.id,
        flow_id=task.flow_id,
        title=task.title,
        created_at=task.created_at,
    )


def _action_summary(
    action: Action,
    *,
    decision: PolicyDecision | None = None,
) -> ActionSummary:
    return ActionSummary(
        id=action.id,
        engagement_id=action.engagement_id,
        task_id=action.task_id,
        action_type=action.action_type,
        normalized_target=action.normalized_target,
        parameter_digest=action.parameter_digest,
        risk_level=action.risk_level,
        idempotency_key=action.idempotency_key,
        state=action.state,
        policy_reason=decision.reason if decision else None,
        requires_dns_recheck=decision.requires_dns_recheck if decision else None,
        created_at=action.created_at,
    )


def _same_protected_action(current: Action, proposed: Action) -> bool:
    return (
        current.task_id == proposed.task_id
        and current.action_type == proposed.action_type
        and current.normalized_target == proposed.normalized_target
        and current.parameter_digest == proposed.parameter_digest
        and current.risk_level is proposed.risk_level
    )


def _audit(
    session: Session,
    engagement_id: EngagementId,
    event_type: str,
    payload: dict[str, object],
    *,
    at: datetime | None = None,
) -> None:
    AuditEventRepository(session).add(
        AuditEvent(
            engagement_id=engagement_id,
            event_type=event_type,
            actor=_AUDIT_ACTOR,
            payload=canonical_json(payload),
            created_at=at or datetime.now(UTC),
        )
    )


def _count_for(session: Session, model: type[Any], column: Any, value: str) -> int:
    return session.scalar(select(func.count()).select_from(model).where(column == value)) or 0


@router.post(
    "/engagements/{engagement_id}/flows",
    response_model=FlowSummary,
    status_code=status.HTTP_201_CREATED,
    summary="Create a testing flow",
)
def create_flow(
    engagement_id: str,
    payload: FlowCreate,
    session: SessionDependency,
) -> FlowSummary:
    normalized_engagement_id = EngagementId(engagement_id)
    if EngagementRepository(session).get(normalized_engagement_id) is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="engagement_not_found")
    flow = Flow(engagement_id=normalized_engagement_id, objective=payload.objective)
    FlowRepository(session).add(flow)
    _audit(session, normalized_engagement_id, "flow.created", {"flow_id": flow.id})
    session.commit()
    return _flow_summary(flow)


@router.get(
    "/engagements/{engagement_id}/flows",
    response_model=FlowListResponse,
    summary="List engagement flows",
)
def list_flows(
    engagement_id: str,
    session: SessionDependency,
    limit: Annotated[int, Query(ge=1, le=100)] = 50,
    offset: Annotated[int, Query(ge=0)] = 0,
) -> FlowListResponse:
    normalized_id = EngagementId(engagement_id)
    if EngagementRepository(session).get(normalized_id) is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="engagement_not_found")
    flows = FlowRepository(session).list_for_engagement(normalized_id, limit=limit, offset=offset)
    return FlowListResponse(
        items=tuple(_flow_summary(item.entity) for item in flows),
        total=_count_for(session, FlowRecord, FlowRecord.engagement_id, engagement_id),
    )


@router.post(
    "/flows/{flow_id}/tasks",
    response_model=TaskSummary,
    status_code=status.HTTP_201_CREATED,
    summary="Create a flow task",
)
def create_task(flow_id: str, payload: TaskCreate, session: SessionDependency) -> TaskSummary:
    stored_flow = FlowRepository(session).get(FlowId(flow_id))
    if stored_flow is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="flow_not_found")
    task = Task(flow_id=stored_flow.entity.id, title=payload.title)
    TaskRepository(session).add(task)
    _audit(
        session,
        stored_flow.entity.engagement_id,
        "task.created",
        {"flow_id": flow_id, "task_id": task.id},
    )
    session.commit()
    return _task_summary(task)


@router.get("/flows/{flow_id}/tasks", response_model=TaskListResponse, summary="List flow tasks")
def list_tasks(
    flow_id: str,
    session: SessionDependency,
    limit: Annotated[int, Query(ge=1, le=100)] = 50,
    offset: Annotated[int, Query(ge=0)] = 0,
) -> TaskListResponse:
    normalized_id = FlowId(flow_id)
    if FlowRepository(session).get(normalized_id) is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="flow_not_found")
    tasks = TaskRepository(session).list_for_flow(normalized_id, limit=limit, offset=offset)
    return TaskListResponse(
        items=tuple(_task_summary(task) for task in tasks),
        total=_count_for(session, TaskRecord, TaskRecord.flow_id, flow_id),
    )


@router.post(
    "/tasks/{task_id}/http-actions",
    response_model=ActionSummary,
    status_code=status.HTTP_201_CREATED,
    summary="Propose and evaluate an HTTP capture action",
)
def create_http_action(
    task_id: str,
    payload: HttpActionCreate,
    response: Response,
    session: SessionDependency,
) -> ActionSummary:
    task = TaskRepository(session).get(TaskId(task_id))
    if task is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="task_not_found")
    stored_flow = FlowRepository(session).get(task.flow_id)
    if stored_flow is None:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="task_flow_missing")
    engagement_id = stored_flow.entity.engagement_id
    stored_engagement = EngagementRepository(session).get(engagement_id)
    scope = ScopeRepository(session).get(engagement_id)
    if stored_engagement is None or scope is None:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="engagement_scope_missing")

    action_id = new_action_id()
    try:
        action_type = normalize_action_type(payload.action_type)
        request = HttpCaptureRequest(
            action_id=action_id,
            method=payload.method,
            target=payload.target,
            headers=tuple(payload.headers.items()),
        )
        action = Action(
            id=action_id,
            engagement_id=engagement_id,
            task_id=task.id,
            action_type=action_type,
            normalized_target=request.target,
            parameter_digest=capture_parameter_digest(request),
            risk_level=classify_risk(action_type),
            idempotency_key=payload.idempotency_key,
        )
    except DomainValidationError as error:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_CONTENT,
            detail=str(error),
        ) from error

    repository = ActionRepository(session)
    existing = repository.get_by_idempotency_key(engagement_id, action.idempotency_key)
    if existing is not None:
        current = existing.entity
        if not _same_protected_action(current, action):
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail="idempotency_key_conflict",
            )
        response.status_code = status.HTTP_200_OK
        return _action_summary(current)

    timestamp = datetime.now(UTC)
    try:
        repository.add(action)
    except IntegrityError as error:
        session.rollback()
        raced = repository.get_by_idempotency_key(engagement_id, action.idempotency_key)
        if raced is None or not _same_protected_action(raced.entity, action):
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail="action_persistence_conflict",
            ) from error
        response.status_code = status.HTTP_200_OK
        return _action_summary(raced.entity)
    stored_proposed = repository.get(action.id)
    if stored_proposed is None:  # pragma: no cover - flush/get invariant
        raise RuntimeError("persisted action could not be reloaded")
    _audit(
        session,
        engagement_id,
        "action.proposed",
        {
            "action_id": action.id,
            "action_type": action.action_type,
            "parameter_digest": action.parameter_digest,
            "target": action.normalized_target,
            "task_id": action.task_id,
        },
        at=timestamp,
    )
    checking = transition_action(action, ActionState.POLICY_CHECK, at=timestamp)
    stored_checking = repository.save(checking, expected_version=stored_proposed.version)
    engagement = stored_engagement.entity
    decision = decide_action(
        checking,
        scope=scope,
        config=PolicyConfig(
            maximum_risk=engagement.maximum_risk,
            destructive_actions_enabled=engagement.destructive_actions_enabled,
        ),
        at=timestamp,
    )
    target_state = {
        DecisionKind.ALLOW: ActionState.QUEUED,
        DecisionKind.APPROVAL_REQUIRED: ActionState.PENDING_APPROVAL,
        DecisionKind.DENY: ActionState.DENIED,
    }[decision.kind]
    evaluated = transition_action(stored_checking.entity, target_state, at=timestamp)
    stored_evaluated = repository.save(evaluated, expected_version=stored_checking.version)
    _audit(
        session,
        engagement_id,
        "policy.decision",
        {
            "action_id": action.id,
            "decision": decision.kind,
            "reason": decision.reason,
            "requires_dns_recheck": decision.requires_dns_recheck,
            "risk_level": decision.risk_level,
            "state": target_state,
        },
        at=timestamp,
    )
    session.commit()
    return _action_summary(stored_evaluated.entity, decision=decision)


@router.get(
    "/engagements/{engagement_id}/actions",
    response_model=ActionListResponse,
    summary="List engagement actions",
)
def list_actions(
    engagement_id: str,
    session: SessionDependency,
    limit: Annotated[int, Query(ge=1, le=100)] = 50,
    offset: Annotated[int, Query(ge=0)] = 0,
) -> ActionListResponse:
    normalized_id = EngagementId(engagement_id)
    if EngagementRepository(session).get(normalized_id) is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="engagement_not_found")
    actions = ActionRepository(session).list_for_engagement(
        normalized_id,
        limit=limit,
        offset=offset,
    )
    return ActionListResponse(
        items=tuple(_action_summary(item.entity) for item in actions),
        total=_count_for(session, ActionRecord, ActionRecord.engagement_id, engagement_id),
    )


@router.get("/actions/{action_id}", response_model=ActionSummary, summary="Get an action")
def get_action(action_id: str, session: SessionDependency) -> ActionSummary:
    stored = ActionRepository(session).get(ActionId(action_id))
    if stored is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="action_not_found")
    return _action_summary(stored.entity)


@router.get(
    "/engagements/{engagement_id}/audit-events",
    response_model=AuditEventListResponse,
    summary="List engagement audit events",
)
def list_audit_events(
    engagement_id: str,
    session: SessionDependency,
    limit: Annotated[int, Query(ge=1, le=100)] = 50,
    offset: Annotated[int, Query(ge=0)] = 0,
) -> AuditEventListResponse:
    normalized_id = EngagementId(engagement_id)
    if EngagementRepository(session).get(normalized_id) is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="engagement_not_found")
    events = AuditEventRepository(session).list_for_engagement(
        normalized_id,
        limit=limit,
        offset=offset,
    )
    return AuditEventListResponse(
        items=tuple(
            AuditEventSummary(
                id=event.id,
                engagement_id=event.engagement_id,
                event_type=event.event_type,
                actor=event.actor,
                payload=json.loads(event.payload),
                created_at=event.created_at,
            )
            for event in events
        ),
        total=_count_for(
            session,
            AuditEventRecord,
            AuditEventRecord.engagement_id,
            engagement_id,
        ),
    )
