"""Authenticated finding review endpoints."""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from vuln_proof_claw.api.audit import record_audit_event
from vuln_proof_claw.api.auth import AuthenticatedPrincipal, require_operator_if_configured
from vuln_proof_claw.api.dependencies import get_session
from vuln_proof_claw.api.schemas.findings import FindingReviewRequest, FindingReviewSummary
from vuln_proof_claw.domain.enums import FindingStatus, VerificationMethod
from vuln_proof_claw.domain.errors import DomainValidationError
from vuln_proof_claw.domain.finding import review_finding
from vuln_proof_claw.domain.identifiers import EngagementId, EvidenceId, FindingId
from vuln_proof_claw.domain.models import Finding
from vuln_proof_claw.evidence.persistence import PersistentEvidenceStore
from vuln_proof_claw.evidence.store import InvalidEvidenceError
from vuln_proof_claw.persistence.models import ActionRecord, EvidencePayloadRecord, EvidenceRecord
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


def _validate_finding_evidence(session: Session, finding: Finding) -> None:
    """Fail closed if a claimed finding has missing, foreign, or altered evidence.

    This verifies provenance and byte integrity, not whether the bytes prove the
    security claim. The reviewer records that semantic judgment separately.
    """
    engagement_id = finding.engagement_id
    metadata_count = session.scalar(
        select(func.count())
        .select_from(EvidenceRecord)
        .join(ActionRecord, EvidenceRecord.action_id == ActionRecord.id)
        .where(ActionRecord.engagement_id == engagement_id)
    )
    payload_count = session.scalar(
        select(func.count())
        .select_from(EvidencePayloadRecord)
        .where(EvidencePayloadRecord.engagement_id == engagement_id)
    )
    if metadata_count != payload_count:
        raise HTTPException(status_code=409, detail="finding_evidence_invalid")

    store = PersistentEvidenceStore(session)
    integrity = store.verify_engagement(engagement_id)
    if not integrity.valid:
        raise HTTPException(status_code=409, detail="finding_evidence_integrity_failed")

    raw_by_id: dict[EvidenceId, bytes] = {}
    for evidence_id in (*finding.evidence_ids, *finding.control_evidence_ids):
        try:
            stored = store.get_for_engagement(engagement_id, evidence_id)
        except InvalidEvidenceError as error:
            raise HTTPException(status_code=409, detail="finding_evidence_invalid") from error
        if stored is None:
            raise HTTPException(status_code=409, detail="finding_evidence_invalid")
        action = session.get(ActionRecord, stored.evidence.action_id)
        if action is None or action.engagement_id != engagement_id:
            raise HTTPException(status_code=409, detail="finding_evidence_invalid")
        raw_by_id[evidence_id] = stored.raw_content
    if finding.verification_method is VerificationMethod.DIFFERENTIAL and any(
        raw_by_id[control] == raw_by_id[payload]
        for control in finding.control_evidence_ids
        for payload in finding.evidence_ids
    ):
        raise HTTPException(status_code=409, detail="finding_control_not_distinct")


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
    requested_status = FindingStatus(payload.status)
    if requested_status is FindingStatus.VERIFIED and payload.comment is None:
        raise HTTPException(status_code=409, detail="verification_rationale_required")
    try:
        reviewed = review_finding(
            stored.entity,
            requested_status,
            verification_method=(
                VerificationMethod(payload.verification_method)
                if payload.verification_method is not None
                else None
            ),
            control_evidence_ids=(
                tuple(EvidenceId(item) for item in payload.control_evidence_ids)
                if payload.control_evidence_ids is not None
                else None
            ),
        )
        if requested_status is FindingStatus.VERIFIED:
            _validate_finding_evidence(session, reviewed)
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
            "verification_method": (
                saved.entity.verification_method.value
                if saved.entity.verification_method is not None
                else None
            ),
            "evidence_ids": saved.entity.evidence_ids,
            "control_evidence_ids": saved.entity.control_evidence_ids,
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
        control_evidence_ids=saved.entity.control_evidence_ids,
        version=saved.version,
        reviewed_at=reviewed_at,
        reviewed_by=principal.identity,
    )
