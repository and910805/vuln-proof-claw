"""Finding review transition rules.

The state invariants -- what a verified finding must carry, and what a HIGH or
CRITICAL claim must state -- live in ``Finding.__post_init__`` so that every
writer is bound by them, not only the review endpoint. ``dataclasses.replace``
re-runs ``__post_init__``, so the transition below inherits them for free and
only has to police the parts that are genuinely about the transition.
"""

from __future__ import annotations

from dataclasses import replace

from vuln_proof_claw.domain.enums import FindingStatus, VerificationMethod
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


def requires_control_evidence(finding: Finding) -> bool:
    """Return whether this finding must carry a baseline or negative control.

    Only a differential claim owes a comparison. Severity says how bad a
    finding is, not what kind of observation established it: a cookie either
    carries ``HttpOnly`` or it does not, and there is no baseline to hold that
    against.
    """
    return finding.verification_method is VerificationMethod.DIFFERENTIAL


def review_finding(finding: Finding, status: FindingStatus) -> Finding:
    """Return a reviewed finding while enforcing the lifecycle rules."""
    if status not in _REVIEWABLE:
        raise DomainValidationError("finding review must use a review status")
    if finding.status is status:
        return finding
    if finding.status is FindingStatus.VERIFIED and status is FindingStatus.PENDING_VERIFICATION:
        raise DomainValidationError("verified findings must be reopened for manual review first")
    if finding.status is FindingStatus.REJECTED and status is FindingStatus.PENDING_VERIFICATION:
        raise DomainValidationError("rejected findings must be reopened for manual review first")
    return replace(finding, status=status)
