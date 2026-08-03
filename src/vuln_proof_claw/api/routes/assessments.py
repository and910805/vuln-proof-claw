"""Operator API for bounded, evidence-backed Web assessments."""

from __future__ import annotations

from collections.abc import Callable
from typing import Annotated, cast

from fastapi import APIRouter, Depends, Header, HTTPException, Query, Request, Response, status
from sqlalchemy.orm import Session

from vuln_proof_claw.api.auth import AuthenticatedPrincipal, require_operator_if_configured
from vuln_proof_claw.api.dependencies import get_session
from vuln_proof_claw.api.schemas.assessments import (
    AssessmentCreate,
    AssessmentHistoryItem,
    AssessmentListResponse,
    AssessmentSummary,
)
from vuln_proof_claw.assessment.discovery import DISCOVERY_PRESETS
from vuln_proof_claw.assessment.service import (
    AssessmentConflictError,
    AssessmentError,
    PassiveAssessmentResult,
    PassiveAssessmentService,
)
from vuln_proof_claw.config.settings import Settings
from vuln_proof_claw.domain.errors import DomainValidationError
from vuln_proof_claw.domain.identifiers import ActionId, EngagementId, ProjectId
from vuln_proof_claw.execution.http_capture import HttpCaptureLimits, HttpCaptureTransport
from vuln_proof_claw.persistence.repositories import ScopeRepository
from vuln_proof_claw.policy.scope import EngagementScope

router = APIRouter(tags=["assessments"])
SessionDependency = Annotated[Session, Depends(get_session)]
OperatorDependency = Annotated[
    AuthenticatedPrincipal,
    Depends(require_operator_if_configured),
]
AssessmentTransportFactory = Callable[[EngagementScope], HttpCaptureTransport]


def _summary(result: PassiveAssessmentResult) -> AssessmentSummary:
    prefix = f"/api/v1/engagements/{result.engagement_id}"
    return AssessmentSummary(
        action_id=result.action_id,
        engagement_id=result.engagement_id,
        state=result.state,
        evidence_ids=result.evidence_ids,
        finding_ids=result.finding_ids,
        findings_count=len(result.finding_ids),
        error_code=result.error_code,
        replayed=result.replayed,
        pages_scanned=result.pages_scanned,
        crawl_truncated=result.crawl_truncated,
        active_probes_run=result.active_probes_run,
        active_probe_truncated=result.active_probe_truncated,
        report_url=f"{prefix}/report",
        markdown_report_url=f"{prefix}/report.md",
        html_report_url=f"{prefix}/report.html",
        sarif_report_url=f"{prefix}/report.sarif",
        bundle_report_url=f"{prefix}/report.bundle.zip",
    )


@router.get(
    "/assessments",
    response_model=AssessmentListResponse,
    summary="List persisted passive assessments",
)
def list_assessments(
    session: SessionDependency,
    project_id: Annotated[str | None, Query()] = None,
    limit: Annotated[int, Query(ge=1, le=100)] = 50,
    offset: Annotated[int, Query(ge=0)] = 0,
) -> AssessmentListResponse:
    """Return newest-first assessment history without initiating network activity."""
    page = PassiveAssessmentService(session).list_history(
        project_id=ProjectId(project_id) if project_id else None,
        limit=limit,
        offset=offset,
    )
    return AssessmentListResponse(
        items=tuple(
            AssessmentHistoryItem(
                action_id=item.action_id,
                engagement_id=item.engagement_id,
                project_id=item.project_id,
                target=item.target,
                state=item.state,
                created_at=item.created_at,
                completed_at=item.completed_at,
                evidence_count=item.evidence_count,
                findings_count=item.findings_count,
                error_code=item.error_code,
                report_url=f"/api/v1/engagements/{item.engagement_id}/report",
                markdown_report_url=f"/api/v1/engagements/{item.engagement_id}/report.md",
                bundle_report_url=(
                    f"/api/v1/engagements/{item.engagement_id}/report.bundle.zip"
                ),
            )
            for item in page.items
        ),
        total=page.total,
    )


@router.post(
    "/engagements/{engagement_id}/assessments",
    response_model=AssessmentSummary,
    status_code=status.HTTP_201_CREATED,
    summary="Run one scoped Web assessment",
)
def create_assessment(  # noqa: PLR0913, PLR0917 - explicit HTTP dependencies
    engagement_id: str,
    payload: AssessmentCreate,
    request: Request,
    response: Response,
    session: SessionDependency,
    principal: OperatorDependency,
    idempotency_key: Annotated[
        str, Header(alias="Idempotency-Key", min_length=1, max_length=200)
    ],
) -> AssessmentSummary:
    normalized_key = idempotency_key.strip()
    if not normalized_key:
        raise HTTPException(status_code=422, detail="idempotency_key_must_not_be_blank")
    settings = cast("Settings", request.app.state.settings)
    factory = getattr(request.app.state, "assessment_transport_factory", None)
    if factory is None or not settings.assessment.enabled:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="assessment_execution_not_ready",
        )
    normalized_id = EngagementId(engagement_id)
    scope = ScopeRepository(session).get(normalized_id)
    if scope is None:
        raise HTTPException(status_code=404, detail="engagement_not_found")
    transport = cast("AssessmentTransportFactory", factory)(scope)
    try:
        limits = HttpCaptureLimits(
            timeout_seconds=settings.assessment.timeout_seconds,
            max_response_bytes=settings.assessment.max_response_bytes,
        )
        service = PassiveAssessmentService(session)
        result = service.run(
            normalized_id,
            payload.target,
            normalized_key,
            principal.identity,
            transport,
            limits=limits,
            user_agent=settings.assessment.user_agent,
            include_conventional=DISCOVERY_PRESETS[payload.preset].include_conventional,
        )
        result = service.crawl(
            normalized_id,
            result,
            normalized_key,
            principal.identity,
            transport,
            limits=limits,
            user_agent=settings.assessment.user_agent,
            preset_name=payload.preset,
        )
        if payload.mode == "active-safe":
            result = service.probe_openapi(
                normalized_id,
                result,
                normalized_key,
                principal.identity,
                transport,
                limits=limits,
                user_agent=settings.assessment.user_agent,
            )
    except DomainValidationError as error:
        raise HTTPException(status_code=422, detail=str(error)) from error
    except AssessmentConflictError as error:
        raise HTTPException(status_code=409, detail=str(error)) from error
    except AssessmentError as error:
        raise HTTPException(status_code=404, detail=str(error)) from error
    if result.replayed:
        response.status_code = status.HTTP_200_OK
    return _summary(result)


@router.get(
    "/engagements/{engagement_id}/assessments/{action_id}",
    response_model=AssessmentSummary,
    summary="Get passive assessment status and result references",
)
def get_assessment(
    engagement_id: str,
    action_id: str,
    session: SessionDependency,
) -> AssessmentSummary:
    try:
        result = PassiveAssessmentService(session).get(
            EngagementId(engagement_id),
            ActionId(action_id),
        )
    except AssessmentError as error:
        raise HTTPException(status_code=404, detail=str(error)) from error
    return _summary(result)
