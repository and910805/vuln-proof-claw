"""Lead lifecycle rules: deduplication, ranking, eligibility, and promotion.

Two invariants are enforced here rather than left to agent judgement:

1. A lead that has already failed is not retried until new evidence arrives.
2. Only a completed verification may promote a lead into a finding.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass, replace
from datetime import datetime

from vuln_proof_claw.agent.scheduler import next_attempt_at
from vuln_proof_claw.domain.autonomous import Lead, MissionBudget, MissionCadence
from vuln_proof_claw.domain.enums import (
    FindingConfidence,
    FindingSeverity,
    FindingStatus,
    LeadStatus,
    VerificationMethod,
)
from vuln_proof_claw.domain.errors import DomainValidationError
from vuln_proof_claw.domain.identifiers import EvidenceId
from vuln_proof_claw.domain.models import SEVERITY_REQUIRES_STATED_METHOD, Finding

_CONFIDENCE_WEIGHT = 60
_RECENCY_WEIGHT = 20
_ATTEMPT_PENALTY = 8
_FAILURE_PENALTY = 12
_MAXIMUM_PRIORITY = 100
_RECENT_EVIDENCE_SECONDS = 86_400


@dataclass(frozen=True, slots=True)
class LeadEligibility:
    """Auditable result of deciding whether a lead may be worked on now."""

    eligible: bool
    reason: str

    def __bool__(self) -> bool:
        return self.eligible


@dataclass(frozen=True, slots=True)
class VerificationOutcome:
    """An independent verifier's structured judgement about a lead.

    The Verifier answers each question; the verdict itself is computed by code so that
    a confident-sounding narrative cannot promote an unproven lead to a finding.
    """

    reproducible: bool
    expected_behavior: bool
    proves_security_impact: bool
    requires_destructive_testing: bool
    vulnerability_class: str
    affected_target: str
    rationale: str
    evidence_ids: tuple[EvidenceId, ...] = ()
    severity: FindingSeverity = FindingSeverity.INFORMATIONAL
    confidence: FindingConfidence = FindingConfidence.MEDIUM
    remediation: str = "Review the evidence and apply the relevant security control."

    verification_method: VerificationMethod | None = None
    """How the claim was established: a single observation, or a comparison.

    Deliberately without a default. A finding at high severity or above must state
    this, and choosing one here on the verifier's behalf would forge the answer to the
    question a reviewer most wants to ask. A verifier that does not know says nothing,
    and promotion then refuses rather than inventing it.
    """

    control_evidence_ids: tuple[EvidenceId, ...] = ()
    """The responses the finding's evidence was compared against.

    A differential claim is a claim about a difference, so it is only as good as what
    sat on the other side. Required when the method is differential: without the
    control, "this identity saw the record" is an observation, not a comparison.
    """

    def __post_init__(self) -> None:
        for name in ("vulnerability_class", "affected_target", "rationale", "remediation"):
            if not str(getattr(self, name)).strip():
                raise DomainValidationError(f"{name} must not be empty")
        if (
            self.severity in SEVERITY_REQUIRES_STATED_METHOD
            and self.verification_method is None
        ):
            raise DomainValidationError(
                f"a {self.severity.value} outcome must state a verification_method"
            )
        if (
            self.verification_method is VerificationMethod.DIFFERENTIAL
            and not self.control_evidence_ids
        ):
            raise DomainValidationError(
                "a differential outcome must carry the control it compared against"
            )


def dedupe_key(*, category: str, target: str, hypothesis: str) -> str:
    """Return a stable key identifying one hypothesis about one target.

    Leads sharing a key are the same investigation and must not be duplicated across
    cycles, which is what keeps a restarting controller from re-queuing known work.
    """
    for name, value in (
        ("category", category),
        ("target", target),
        ("hypothesis", hypothesis),
    ):
        if not value.strip():
            raise DomainValidationError(f"{name} must not be empty")
    material = "\x1f".join(
        part.strip().lower() for part in (category, target, hypothesis)
    ).encode()
    return hashlib.sha256(material).hexdigest()[:32]


def rank_lead(lead: Lead, *, now: datetime) -> int:
    """Return a deterministic 0-100 priority for scheduling order.

    Confidence dominates, recent supporting evidence raises urgency, and repeated
    attempts and failures push a lead down so that it cannot monopolise the budget.
    """
    if now.tzinfo is None or now.utcoffset() is None:
        raise DomainValidationError("now must be timezone-aware")
    score = int(lead.confidence * _CONFIDENCE_WEIGHT)
    reference = lead.last_attempt_at or lead.created_at
    if (now - reference).total_seconds() <= _RECENT_EVIDENCE_SECONDS and lead.evidence_ids:
        score += _RECENCY_WEIGHT
    score -= lead.attempt_count * _ATTEMPT_PENALTY
    score -= lead.failure_count * _FAILURE_PENALTY
    return max(0, min(_MAXIMUM_PRIORITY, score))


def evaluate_eligibility(
    lead: Lead,
    *,
    now: datetime,
    budget: MissionBudget,
    has_new_evidence: bool,
) -> LeadEligibility:
    """Decide whether the controller may work this lead in the current cycle.

    ``has_new_evidence`` must be derived from stored observations and change events,
    never from the agent's own assertion that something is worth retrying.
    """
    if now.tzinfo is None or now.utcoffset() is None:
        raise DomainValidationError("now must be timezone-aware")
    if not lead.status.eligible_for_scheduling:
        return LeadEligibility(eligible=False, reason=f"status_{lead.status.value}")
    if lead.blocked_reason:
        return LeadEligibility(eligible=False, reason="lead_blocked")
    if lead.attempt_count >= budget.maximum_lead_attempts:
        return LeadEligibility(eligible=False, reason="attempt_limit_reached")
    if lead.next_attempt_at is not None and now < lead.next_attempt_at:
        return LeadEligibility(eligible=False, reason="cooldown_active")
    if lead.failure_count > 0 and not has_new_evidence:
        return LeadEligibility(eligible=False, reason="no_new_evidence_since_failure")
    return LeadEligibility(eligible=True, reason="eligible")


def begin_attempt(lead: Lead, *, now: datetime) -> Lead:
    """Move a lead into investigation and count the attempt.

    The attempt is counted at the start, not on completion, so that a crash during
    investigation cannot produce unbounded retries against a target.
    """
    return replace(
        lead,
        status=LeadStatus.INVESTIGATING,
        attempt_count=lead.attempt_count + 1,
        last_attempt_at=now,
        next_attempt_at=None,
        updated_at=now,
    )


def record_failure(
    lead: Lead,
    *,
    reason: str,
    cadence: MissionCadence,
    now: datetime,
) -> Lead:
    """Record an unsuccessful investigation and apply the backoff cooldown."""
    if not reason.strip():
        raise DomainValidationError("reason must not be empty")
    failed = replace(
        lead,
        failure_count=lead.failure_count + 1,
        last_attempt_at=lead.last_attempt_at or now,
        last_reasoning_summary=reason,
        updated_at=now,
    )
    return replace(
        failed,
        status=LeadStatus.WAITING,
        next_attempt_at=next_attempt_at(failed, cadence, now=now),
    )


def record_blocked(lead: Lead, *, reason: str, now: datetime) -> Lead:
    """Park a lead that requires a human decision before it can proceed."""
    if not reason.strip():
        raise DomainValidationError("reason must not be empty")
    return replace(
        lead,
        status=LeadStatus.NEEDS_APPROVAL,
        blocked_reason=reason,
        next_attempt_at=None,
        updated_at=now,
    )


def record_rejected(lead: Lead, *, reason: str, now: datetime) -> Lead:
    """Close a lead that policy or verification has ruled out."""
    if not reason.strip():
        raise DomainValidationError("reason must not be empty")
    return replace(
        lead,
        status=LeadStatus.REJECTED,
        last_reasoning_summary=reason,
        next_attempt_at=None,
        updated_at=now,
    )


def mark_stale(lead: Lead, *, now: datetime) -> Lead:
    """Mark a long-untouched lead as stale without discarding its history."""
    return replace(lead, status=LeadStatus.STALE, next_attempt_at=None, updated_at=now)


def reawaken(lead: Lead, *, reason: str, now: datetime) -> Lead:
    """Return a stale or rejected lead to the queue because new evidence arrived."""
    if not reason.strip():
        raise DomainValidationError("reason must not be empty")
    if not lead.status.reawakenable:
        raise DomainValidationError("only stale, rejected, or waiting leads may be reawakened")
    return replace(
        lead,
        status=LeadStatus.QUEUED,
        blocked_reason=None,
        last_reasoning_summary=reason,
        next_attempt_at=None,
        updated_at=now,
    )


def verification_verdict(outcome: VerificationOutcome) -> FindingStatus:
    """Compute the verdict from the verifier's structured answers.

    Anything that would need destructive testing to prove stops here and becomes a
    human decision; it is never escalated automatically.
    """
    if outcome.requires_destructive_testing:
        return FindingStatus.NEEDS_MANUAL_REVIEW
    if not outcome.reproducible:
        return FindingStatus.REJECTED
    if outcome.expected_behavior:
        return FindingStatus.REJECTED
    if not outcome.proves_security_impact:
        return FindingStatus.REJECTED
    if not outcome.evidence_ids:
        return FindingStatus.REJECTED
    return FindingStatus.VERIFIED


def promote_to_finding(
    lead: Lead,
    outcome: VerificationOutcome,
    *,
    now: datetime,
) -> tuple[Lead, Finding | None]:
    """Apply a verification outcome to a lead, creating a finding only when proven.

    This is the only path from a lead to a finding anywhere in the system. A scanner
    result, a heuristic, or a planner's confidence cannot reach a finding without
    passing through a verification outcome that carries evidence.
    """
    verdict = verification_verdict(outcome)
    if verdict is FindingStatus.REJECTED:
        return (record_rejected(lead, reason=outcome.rationale, now=now), None)
    if verdict is FindingStatus.NEEDS_MANUAL_REVIEW:
        return (record_blocked(lead, reason="requires_manual_review", now=now), None)

    finding = Finding(
        engagement_id=lead.engagement_id,
        title=lead.title,
        vulnerability_class=outcome.vulnerability_class,
        affected_target=outcome.affected_target,
        evidence_ids=outcome.evidence_ids,
        status=FindingStatus.VERIFIED,
        severity=outcome.severity,
        confidence=outcome.confidence,
        remediation=outcome.remediation,
        verification_method=outcome.verification_method,
        control_evidence_ids=outcome.control_evidence_ids,
        created_at=now,
    )
    verified = replace(
        lead,
        status=LeadStatus.VERIFIED,
        evidence_ids=tuple(dict.fromkeys((*lead.evidence_ids, *outcome.evidence_ids))),
        related_findings=(*lead.related_findings, finding.id),
        last_reasoning_summary=outcome.rationale,
        blocked_reason=None,
        next_attempt_at=None,
        updated_at=now,
    )
    return (verified, finding)


__all__ = [
    "LeadEligibility",
    "VerificationOutcome",
    "begin_attempt",
    "dedupe_key",
    "evaluate_eligibility",
    "mark_stale",
    "promote_to_finding",
    "rank_lead",
    "reawaken",
    "record_blocked",
    "record_failure",
    "record_rejected",
    "verification_verdict",
]
