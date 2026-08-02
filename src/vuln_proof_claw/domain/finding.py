"""Finding review transition rules."""

from __future__ import annotations

from dataclasses import replace

from vuln_proof_claw.domain.enums import FindingStatus
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


def review_finding(finding: Finding, status: FindingStatus) -> Finding:
    """Return a reviewed finding while enforcing evidence and lifecycle rules."""
    if status not in _REVIEWABLE:
        raise DomainValidationError("finding review must use a review status")
    if status is FindingStatus.VERIFIED and not finding.evidence_ids:
        raise DomainValidationError("verified findings require at least one evidence record")
    if finding.status is status:
        return finding
    if finding.status is FindingStatus.VERIFIED and status is FindingStatus.PENDING_VERIFICATION:
        raise DomainValidationError("verified findings must be reopened for manual review first")
    if finding.status is FindingStatus.REJECTED and status is FindingStatus.PENDING_VERIFICATION:
        raise DomainValidationError("rejected findings must be reopened for manual review first")
    return replace(finding, status=status)
