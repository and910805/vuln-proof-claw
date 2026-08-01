"""Control-plane endpoints consumed by the Web console."""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Annotated, Any

from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from vuln_proof_claw.api.dependencies import get_session
from vuln_proof_claw.api.schemas.console import (
    DashboardCounts,
    DashboardSummaryResponse,
    EngagementCreate,
    EngagementListResponse,
    EngagementSummary,
    ProjectCreate,
    ProjectListResponse,
    ProjectSummary,
    ScopeDefinition,
    ScopeEvaluationRequest,
    ScopeEvaluationResponse,
)
from vuln_proof_claw.domain.enums import ActionState
from vuln_proof_claw.domain.errors import DomainValidationError
from vuln_proof_claw.domain.identifiers import EngagementId, ProjectId
from vuln_proof_claw.domain.models import Engagement, Project
from vuln_proof_claw.persistence.models import (
    ActionRecord,
    EngagementRecord,
    EvidenceRecord,
    FindingRecord,
    ProjectRecord,
)
from vuln_proof_claw.persistence.repositories import (
    EngagementRepository,
    ProjectRepository,
    ScopeRepository,
)
from vuln_proof_claw.policy.scope import EngagementScope, evaluate_scope

router = APIRouter(tags=["console"])
SessionDependency = Annotated[Session, Depends(get_session)]


def _project_summary(project: Project) -> ProjectSummary:
    return ProjectSummary(
        id=project.id,
        name=project.name,
        created_at=project.created_at,
    )


def _scope_definition(scope: EngagementScope) -> ScopeDefinition:
    return ScopeDefinition(
        allowed_hostnames=tuple(sorted(scope.allowed_hostnames)),
        allowed_cidrs=tuple(str(network) for network in scope.allowed_networks),
        allowed_ports=tuple(sorted(scope.allowed_ports)),
        allowed_schemes=tuple(sorted(scope.allowed_schemes)),
        allowed_paths=scope.allowed_paths,
        denied_hostnames=tuple(sorted(scope.denied_hostnames)),
        denied_cidrs=tuple(str(network) for network in scope.denied_networks),
        denied_paths=scope.denied_paths,
        valid_from=scope.valid_from,
        valid_until=scope.valid_until,
    )


def _engagement_summary(
    engagement: Engagement,
    scope: EngagementScope,
) -> EngagementSummary:
    return EngagementSummary(
        id=engagement.id,
        project_id=engagement.project_id,
        name=engagement.name,
        starts_at=engagement.starts_at,
        ends_at=engagement.ends_at,
        maximum_risk=engagement.maximum_risk,
        destructive_actions_enabled=engagement.destructive_actions_enabled,
        created_at=engagement.created_at,
        scope=_scope_definition(scope),
    )


def _count(session: Session, model: type[Any]) -> int:
    return session.scalar(select(func.count()).select_from(model)) or 0


@router.get(
    "/dashboard/summary",
    response_model=DashboardSummaryResponse,
    summary="Web console dashboard summary",
)
def dashboard_summary(session: SessionDependency) -> DashboardSummaryResponse:
    """Return persisted counts without claiming unavailable execution capabilities."""
    active_states = (
        ActionState.PROPOSED.value,
        ActionState.POLICY_CHECK.value,
        ActionState.PENDING_APPROVAL.value,
        ActionState.QUEUED.value,
        ActionState.RUNNING.value,
    )
    active_actions = (
        session.scalar(
            select(func.count())
            .select_from(ActionRecord)
            .where(ActionRecord.state.in_(active_states))
        )
        or 0
    )
    pending_approvals = (
        session.scalar(
            select(func.count())
            .select_from(ActionRecord)
            .where(ActionRecord.state == ActionState.PENDING_APPROVAL.value)
        )
        or 0
    )
    recent_projects = ProjectRepository(session).list(limit=5)
    return DashboardSummaryResponse(
        counts=DashboardCounts(
            projects=_count(session, ProjectRecord),
            engagements=_count(session, EngagementRecord),
            active_actions=active_actions,
            pending_approvals=pending_approvals,
            evidence=_count(session, EvidenceRecord),
            findings=_count(session, FindingRecord),
        ),
        recent_projects=tuple(_project_summary(project) for project in recent_projects),
    )


@router.get(
    "/projects",
    response_model=ProjectListResponse,
    summary="List projects",
)
def list_projects(
    session: SessionDependency,
    limit: Annotated[int, Query(ge=1, le=100)] = 50,
    offset: Annotated[int, Query(ge=0)] = 0,
) -> ProjectListResponse:
    """List projects newest first."""
    projects = ProjectRepository(session).list(limit=limit, offset=offset)
    return ProjectListResponse(
        items=tuple(_project_summary(project) for project in projects),
        total=_count(session, ProjectRecord),
    )


@router.post(
    "/projects",
    response_model=ProjectSummary,
    status_code=status.HTTP_201_CREATED,
    summary="Create a project",
)
def create_project(payload: ProjectCreate, session: SessionDependency) -> ProjectSummary:
    """Create a project through the domain model and commit it atomically."""
    project = Project(name=payload.name)
    ProjectRepository(session).add(project)
    session.commit()
    return _project_summary(project)


@router.post(
    "/projects/{project_id}/engagements",
    response_model=EngagementSummary,
    status_code=status.HTTP_201_CREATED,
    summary="Create a scoped engagement",
)
def create_engagement(
    project_id: str,
    payload: EngagementCreate,
    session: SessionDependency,
) -> EngagementSummary:
    project = ProjectRepository(session).get(ProjectId(project_id))
    if project is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="project_not_found")
    try:
        engagement = Engagement(
            project_id=project.id,
            name=payload.name,
            starts_at=payload.starts_at,
            ends_at=payload.ends_at,
            maximum_risk=payload.maximum_risk,
            destructive_actions_enabled=payload.destructive_actions_enabled,
        )
        scope_values = payload.scope.model_dump()
        scope_values["valid_from"] = scope_values["valid_from"] or engagement.starts_at
        scope_values["valid_until"] = scope_values["valid_until"] or engagement.ends_at
        scope = EngagementScope.create(**scope_values)
        if scope.valid_from is None or scope.valid_from < engagement.starts_at:
            raise DomainValidationError("scope must not start before its engagement")
        if scope.valid_until is None or scope.valid_until > engagement.ends_at:
            raise DomainValidationError("scope must not end after its engagement")
    except DomainValidationError as error:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_CONTENT,
            detail=str(error),
        ) from error
    EngagementRepository(session).add(engagement)
    ScopeRepository(session).add(engagement.id, scope)
    session.commit()
    return _engagement_summary(engagement, scope)


@router.get(
    "/projects/{project_id}/engagements",
    response_model=EngagementListResponse,
    summary="List project engagements",
)
def list_engagements(
    project_id: str,
    session: SessionDependency,
    limit: Annotated[int, Query(ge=1, le=100)] = 50,
    offset: Annotated[int, Query(ge=0)] = 0,
) -> EngagementListResponse:
    normalized_project_id = ProjectId(project_id)
    if ProjectRepository(session).get(normalized_project_id) is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="project_not_found")
    repository = EngagementRepository(session)
    scope_repository = ScopeRepository(session)
    engagements = repository.list_for_project(
        normalized_project_id,
        limit=limit,
        offset=offset,
    )
    items: list[EngagementSummary] = []
    for stored in engagements:
        scope = scope_repository.get(stored.entity.id)
        if scope is None:
            continue
        items.append(_engagement_summary(stored.entity, scope))
    total = session.scalar(
        select(func.count())
        .select_from(EngagementRecord)
        .where(EngagementRecord.project_id == normalized_project_id)
    ) or 0
    return EngagementListResponse(items=tuple(items), total=total)


@router.get(
    "/engagements/{engagement_id}",
    response_model=EngagementSummary,
    summary="Get a scoped engagement",
)
def get_engagement(engagement_id: str, session: SessionDependency) -> EngagementSummary:
    normalized_id = EngagementId(engagement_id)
    stored = EngagementRepository(session).get(normalized_id)
    scope = ScopeRepository(session).get(normalized_id)
    if stored is None or scope is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="engagement_not_found")
    return _engagement_summary(stored.entity, scope)


@router.post(
    "/engagements/{engagement_id}/scope/evaluate",
    response_model=ScopeEvaluationResponse,
    summary="Evaluate a target against persisted scope",
)
def evaluate_engagement_scope(
    engagement_id: str,
    payload: ScopeEvaluationRequest,
    session: SessionDependency,
) -> ScopeEvaluationResponse:
    scope = ScopeRepository(session).get(EngagementId(engagement_id))
    if scope is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="engagement_not_found")
    try:
        decision = evaluate_scope(payload.target, scope, at=datetime.now(UTC))
    except DomainValidationError as error:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_CONTENT,
            detail=str(error),
        ) from error
    return ScopeEvaluationResponse(
        allowed=decision.allowed,
        reason=decision.reason,
        normalized_target=str(decision.target),
        requires_dns_recheck=decision.requires_dns_recheck,
    )
