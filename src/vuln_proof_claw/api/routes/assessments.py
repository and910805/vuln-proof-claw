"""Operator API for one bounded, evidence-backed passive URL assessment."""

from __future__ import annotations

from collections.abc import Callable
from typing import Annotated, cast

from fastapi import APIRouter, Depends, Header, HTTPException, Request, Response, status
from sqlalchemy.orm import Session

from vuln_proof_claw.api.auth import AuthenticatedPrincipal, require_operator_if_configured
from vuln_proof_claw.api.dependencies import get_session
from vuln_proof_claw.api.schemas.assessments import AssessmentCreate, AssessmentSummary
from vuln_proof_claw.assessment.service import (
    AssessmentConflictError,
    AssessmentError,
    PassiveAssessmentResult,
    PassiveAssessmentService,
)
from vuln_proof_claw.config.settings import Settings
from vuln_proof_claw.domain.errors import DomainValidationError
from vuln_proof_claw.domain.identifiers import ActionId, EngagementId
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
        report_url=f"{prefix}/report",
        markdown_report_url=f"{prefix}/report.md",
    )


@router.post(
    "/engagements/{engagement_id}/assessments",
    response_model=AssessmentSummary,
    status_code=status.HTTP_201_CREATED,
    summary="Run one scoped passive URL assessment",
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
        result = PassiveAssessmentService(session).run(
            normalized_id,
            payload.target,
            normalized_key,
            principal.identity,
            transport,
            limits=HttpCaptureLimits(
                timeout_seconds=settings.assessment.timeout_seconds,
                max_response_bytes=settings.assessment.max_response_bytes,
            ),
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
