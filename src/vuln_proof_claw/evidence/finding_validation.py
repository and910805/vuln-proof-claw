"""Persistence boundary for evidence-backed verified findings.

This check proves that linked evidence belongs to the finding's engagement and
that its stored bytes still match the engagement's hash chain. It does not
decide whether those bytes establish the security claim.
"""

from __future__ import annotations

from typing import Literal

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from vuln_proof_claw.domain.enums import FindingStatus, VerificationMethod
from vuln_proof_claw.domain.errors import DomainValidationError
from vuln_proof_claw.domain.identifiers import EvidenceId
from vuln_proof_claw.domain.models import Finding
from vuln_proof_claw.evidence.persistence import PersistentEvidenceStore
from vuln_proof_claw.evidence.store import InvalidEvidenceError
from vuln_proof_claw.persistence.models import ActionRecord, EvidencePayloadRecord, EvidenceRecord

FindingEvidenceCode = Literal[
    "finding_evidence_invalid",
    "finding_evidence_integrity_failed",
    "finding_control_not_distinct",
]


class FindingEvidenceError(Exception):
    """A verified finding could not be supported by persisted evidence."""

    def __init__(self, code: FindingEvidenceCode) -> None:
        self.code = code
        super().__init__(code)


def validate_verified_finding_evidence(session: Session, finding: Finding) -> None:
    """Reject a verified claim with missing, foreign, or altered evidence.

    The check runs before a repository inserts or updates the finding, so a
    rejected claim leaves no verified row or changed review version behind.
    Candidates may still be recorded while their evidence is being gathered.
    """
    if finding.status is not FindingStatus.VERIFIED:
        return

    session.flush()
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
        raise FindingEvidenceError("finding_evidence_invalid")

    store = PersistentEvidenceStore(session)
    integrity = store.verify_engagement(engagement_id)
    if not integrity.valid:
        raise FindingEvidenceError("finding_evidence_integrity_failed")

    raw_by_id: dict[EvidenceId, bytes] = {}
    for evidence_id in (*finding.evidence_ids, *finding.control_evidence_ids):
        try:
            stored = store.get_for_engagement(engagement_id, evidence_id)
        except (InvalidEvidenceError, DomainValidationError) as error:
            raise FindingEvidenceError("finding_evidence_invalid") from error
        if stored is None:
            raise FindingEvidenceError("finding_evidence_invalid")
        action = session.get(ActionRecord, stored.evidence.action_id)
        if action is None or action.engagement_id != engagement_id:
            raise FindingEvidenceError("finding_evidence_invalid")
        raw_by_id[evidence_id] = stored.raw_content

    if finding.verification_method is VerificationMethod.DIFFERENTIAL and any(
        raw_by_id[control] == raw_by_id[payload]
        for control in finding.control_evidence_ids
        for payload in finding.evidence_ids
    ):
        raise FindingEvidenceError("finding_control_not_distinct")
