"""Authenticated finding review endpoints."""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session

from vuln_proof_claw.api.audit import record_audit_event
from vuln_proof_claw.api.auth import AuthenticatedPrincipal, require_operator_if_configured
from vuln_proof_claw.api.dependencies import get_session
from vuln_proof_claw.api.schemas.findings import FindingReviewRequest, FindingReviewSummary
from vuln_proof_claw.domain.enums import FindingStatus
from vuln_proof_claw.domain.errors import DomainValidationError
from vuln_proof_claw.domain.finding import review_finding
from vuln_proof_claw.domain.identifiers import EngagementId, FindingId
from vuln_proof_claw.persistence.repositories import (
    ConcurrentUpdateError,
    EngagementRepository,
    FindingRepository,
)

router = APIRouter(tags=["findings"])
SessionDependency = Annotated[Session, Depends(get_session)]
OperatorDependency = Annotated[
    AuthenticatedPrincipal,
    Depends(require_operator_if_configured),
]


@router.patch(
    "/engagements/{engagement_id}/findings/{finding_id}",
    response_model=FindingReviewSummary,
    summary="Review an evidence-backed finding",
)
def review_finding_endpoint(
    engagement_id: str,
    finding_id: str,
    payload: FindingReviewRequest,
    session: SessionDependency,
    principal: OperatorDependency,
) -> FindingReviewSummary:
    normalized_engagement_id = EngagementId(engagement_id)
    if EngagementRepository(session).get(normalized_engagement_id) is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="engagement_not_found")
    repository = FindingRepository(session)
    stored = repository.get(FindingId(finding_id))
    if stored is None or stored.entity.engagement_id != normalized_engagement_id:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="finding_not_found")
    if stored.version != payload.expected_version:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="finding_version_conflict")
    try:
        reviewed = review_finding(stored.entity, FindingStatus(payload.status))
        saved = repository.save(reviewed, expected_version=stored.version)
    except DomainValidationError as error:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail=str(error)) from error
    except ConcurrentUpdateError as error:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="finding_version_conflict",
        ) from error
    reviewed_at = datetime.now(UTC)
    record_audit_event(
        session,
        normalized_engagement_id,
        "finding.reviewed",
        principal.identity,
        {
            "finding_id": finding_id,
            "status_before": stored.entity.status.value,
            "status_after": saved.entity.status.value,
            "expected_version": payload.expected_version,
            "version": saved.version,
            "comment": payload.comment,
        },
        at=reviewed_at,
    )
    session.commit()
    return FindingReviewSummary(
        id=saved.entity.id,
        engagement_id=saved.entity.engagement_id,
        title=saved.entity.title,
        vulnerability_class=saved.entity.vulnerability_class,
        cwe_id=saved.entity.cwe_id,
        # None stays None: "no method stated" is a value of its own, and
        # rendering it as "observed" would forge the claim the domain refuses.
        verification_method=(
            saved.entity.verification_method.value
            if saved.entity.verification_method is not None
            else None
        ),
        affected_target=saved.entity.affected_target,
        status=saved.entity.status.value,
        severity=saved.entity.severity.value,
        confidence=saved.entity.confidence.value,
        remediation=saved.entity.remediation,
        evidence_ids=saved.entity.evidence_ids,
        version=saved.version,
        reviewed_at=reviewed_at,
        reviewed_by=principal.identity,
    )
