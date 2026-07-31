"""Control-plane endpoints consumed by the Web console."""

from __future__ import annotations

from typing import Annotated, Any

from fastapi import APIRouter, Depends, Query, status
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from vuln_proof_claw.api.dependencies import get_session
from vuln_proof_claw.api.schemas.console import (
    DashboardCounts,
    DashboardSummaryResponse,
    ProjectCreate,
    ProjectListResponse,
    ProjectSummary,
)
from vuln_proof_claw.domain.enums import ActionState
from vuln_proof_claw.domain.models import Project
from vuln_proof_claw.persistence.models import (
    ActionRecord,
    EngagementRecord,
    EvidenceRecord,
    FindingRecord,
    ProjectRecord,
)
from vuln_proof_claw.persistence.repositories import ProjectRepository

router = APIRouter(tags=["console"])
SessionDependency = Annotated[Session, Depends(get_session)]


def _project_summary(project: Project) -> ProjectSummary:
    return ProjectSummary(
        id=project.id,
        name=project.name,
        created_at=project.created_at,
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
