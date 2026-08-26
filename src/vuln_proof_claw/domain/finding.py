"""Finding review transition rules."""

from __future__ import annotations

from dataclasses import replace

from vuln_proof_claw.domain.enums import (
    FindingSeverity,
    FindingStatus,
    VerificationMethod,
)
from vuln_proof_claw.domain.errors import DomainValidationError
from vuln_proof_claw.domain.models import Finding

_REVIEWABLE = frozenset(
    {
        FindingStatus.PENDING_VERIFICATION,
        FindingStatus.VERIFIED,
        FindingStatus.REJECTED,
        FindingStatus.NEEDS_MANUAL_REVIEW,
    }
)

# A payload response only means something next to a response that did not carry
# the payload. Anything claimed at this severity has to show that comparison,
# otherwise a default behaviour of the product reads as a critical defect.
_REQUIRES_DIFFERENTIAL = frozenset({FindingSeverity.HIGH, FindingSeverity.CRITICAL})


def requires_control_evidence(finding: Finding) -> bool:
    """Return whether this finding must carry a baseline or negative control."""
    return (
        finding.verification_method is VerificationMethod.DIFFERENTIAL
        or finding.severity in _REQUIRES_DIFFERENTIAL
    )


def review_finding(finding: Finding, status: FindingStatus) -> Finding:
    """Return a reviewed finding while enforcing evidence and lifecycle rules."""
    if status not in _REVIEWABLE:
        raise DomainValidationError("finding review must use a review status")
    if status is FindingStatus.VERIFIED:
        _check_verification_evidence(finding)
    if finding.status is status:
        return finding
    if finding.status is FindingStatus.VERIFIED and status is FindingStatus.PENDING_VERIFICATION:
        raise DomainValidationError("verified findings must be reopened for manual review first")
    if finding.status is FindingStatus.REJECTED and status is FindingStatus.PENDING_VERIFICATION:
        raise DomainValidationError("rejected findings must be reopened for manual review first")
    return replace(finding, status=status)


def _check_verification_evidence(finding: Finding) -> None:
    if not finding.evidence_ids:
        raise DomainValidationError("verified findings require at least one evidence record")
    if not requires_control_evidence(finding):
        return
    if finding.severity in _REQUIRES_DIFFERENTIAL and (
        finding.verification_method is not VerificationMethod.DIFFERENTIAL
    ):
        raise DomainValidationError("high and critical findings must be verified differentially")
    if not finding.control_evidence_ids:
        raise DomainValidationError(
            "differential verification requires at least one control evidence record"
        )
