"""Tests for lead deduplication, ranking, eligibility, and promotion."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest

from vuln_proof_claw.agent.leads import (
    VerificationOutcome,
    begin_attempt,
    dedupe_key,
    evaluate_eligibility,
    mark_stale,
    promote_to_finding,
    rank_lead,
    reawaken,
    record_blocked,
    record_failure,
    record_rejected,
    verification_verdict,
)
from vuln_proof_claw.domain.autonomous import Lead, MissionBudget, MissionCadence
from vuln_proof_claw.domain.enums import FindingSeverity, FindingStatus, LeadStatus
from vuln_proof_claw.domain.errors import DomainValidationError
from vuln_proof_claw.domain.identifiers import (
    EngagementId,
    EvidenceId,
    MissionId,
    new_engagement_id,
    new_mission_id,
)

NOW = datetime(2026, 10, 4, 12, 0, tzinfo=UTC)
BUDGET = MissionBudget()
CADENCE = MissionCadence()
ENGAGEMENT: EngagementId = new_engagement_id()
MISSION: MissionId = new_mission_id()
EVIDENCE = (EvidenceId("11111111-1111-7111-8111-111111111111"),)


def make_lead(**overrides: object) -> Lead:
    defaults: dict[str, object] = {
        "engagement_id": ENGAGEMENT,
        "mission_id": MISSION,
        "title": "Possible horizontal authorization weakness",
        "hypothesis": "Object ownership may not be enforced consistently",
        "category": "authorization",
        "created_at": NOW,
        "updated_at": NOW,
    }
    defaults.update(overrides)
    return Lead(**defaults)  # type: ignore[arg-type]


def test_dedupe_key_is_stable_and_case_insensitive() -> None:
    first = dedupe_key(category="AuthZ", target="https://api.example.com/orders", hypothesis="IDOR")
    second = dedupe_key(
        category="authz", target="https://api.example.com/orders ", hypothesis=" idor"
    )

    assert first == second
    assert len(first) == 32


def test_dedupe_key_rejects_empty_components() -> None:
    with pytest.raises(DomainValidationError):
        dedupe_key(category="authz", target="", hypothesis="IDOR")


def test_rank_prefers_confidence_and_penalizes_repeated_failure() -> None:
    confident = make_lead(confidence=0.9)
    failing = make_lead(
        confidence=0.9,
        attempt_count=3,
        failure_count=3,
        last_attempt_at=NOW,
    )

    assert rank_lead(confident, now=NOW) > rank_lead(failing, now=NOW)


def test_rank_is_bounded_to_the_priority_range() -> None:
    minimum = make_lead(confidence=0.0, attempt_count=10, failure_count=10, last_attempt_at=NOW)
    maximum = make_lead(confidence=1.0, evidence_ids=EVIDENCE)

    assert rank_lead(minimum, now=NOW) == 0
    assert 0 <= rank_lead(maximum, now=NOW) <= 100


def test_a_failed_lead_is_not_retried_without_new_evidence() -> None:
    lead = make_lead(attempt_count=1, failure_count=1, last_attempt_at=NOW)

    blocked = evaluate_eligibility(lead, now=NOW, budget=BUDGET, has_new_evidence=False)
    unblocked = evaluate_eligibility(lead, now=NOW, budget=BUDGET, has_new_evidence=True)

    assert not blocked
    assert blocked.reason == "no_new_evidence_since_failure"
    assert unblocked


def test_eligibility_respects_cooldown_attempt_limit_and_blocking() -> None:
    cooling = make_lead(next_attempt_at=NOW + timedelta(minutes=5))
    exhausted = make_lead(
        attempt_count=BUDGET.maximum_lead_attempts,
        last_attempt_at=NOW,
    )
    blocked = make_lead(blocked_reason="explicit_approval_required")
    terminal = make_lead(status=LeadStatus.REJECTED)

    assert evaluate_eligibility(cooling, now=NOW, budget=BUDGET, has_new_evidence=True).reason == (
        "cooldown_active"
    )
    assert evaluate_eligibility(
        exhausted, now=NOW, budget=BUDGET, has_new_evidence=True
    ).reason == "attempt_limit_reached"
    assert evaluate_eligibility(blocked, now=NOW, budget=BUDGET, has_new_evidence=True).reason == (
        "lead_blocked"
    )
    assert not evaluate_eligibility(terminal, now=NOW, budget=BUDGET, has_new_evidence=True)


def test_attempt_is_counted_before_the_work_runs() -> None:
    lead = make_lead()

    attempting = begin_attempt(lead, now=NOW)

    assert attempting.status is LeadStatus.INVESTIGATING
    assert attempting.attempt_count == 1
    assert attempting.last_attempt_at == NOW


def test_failure_applies_an_exponential_cooldown() -> None:
    first = record_failure(
        begin_attempt(make_lead(), now=NOW), reason="no_signal", cadence=CADENCE, now=NOW
    )
    second = record_failure(
        begin_attempt(first, now=NOW), reason="no_signal", cadence=CADENCE, now=NOW
    )

    assert first.status is LeadStatus.WAITING
    assert first.next_attempt_at is not None
    assert second.next_attempt_at is not None
    assert second.next_attempt_at > first.next_attempt_at


def test_failure_count_can_never_exceed_attempt_count() -> None:
    attempted = begin_attempt(make_lead(), now=NOW)

    failed = record_failure(attempted, reason="no_signal", cadence=CADENCE, now=NOW)

    assert failed.failure_count == failed.attempt_count == 1
    with pytest.raises(DomainValidationError):
        record_failure(failed, reason="no_signal", cadence=CADENCE, now=NOW)


def test_blocked_and_rejected_transitions_record_their_reason() -> None:
    blocked = record_blocked(make_lead(), reason="explicit_approval_required", now=NOW)
    rejected = record_rejected(make_lead(), reason="scope_denied", now=NOW)

    assert blocked.status is LeadStatus.NEEDS_APPROVAL
    assert blocked.blocked_reason == "explicit_approval_required"
    assert rejected.status is LeadStatus.REJECTED
    assert rejected.last_reasoning_summary == "scope_denied"


def test_only_reawakenable_leads_may_return_to_the_queue() -> None:
    stale = mark_stale(make_lead(), now=NOW)

    revived = reawaken(stale, reason="attack_surface_changed", now=NOW)

    assert revived.status is LeadStatus.QUEUED
    with pytest.raises(DomainValidationError):
        reawaken(make_lead(status=LeadStatus.INVESTIGATING), reason="changed", now=NOW)


def outcome(**overrides: object) -> VerificationOutcome:
    defaults: dict[str, object] = {
        "reproducible": True,
        "expected_behavior": False,
        "proves_security_impact": True,
        "requires_destructive_testing": False,
        "vulnerability_class": "broken_object_level_authorization",
        "affected_target": "https://api.example.com/orders/1",
        "rationale": "Two authorized identities received the same object.",
        "evidence_ids": EVIDENCE,
        "severity": FindingSeverity.HIGH,
    }
    defaults.update(overrides)
    return VerificationOutcome(**defaults)  # type: ignore[arg-type]


@pytest.mark.parametrize(
    ("override", "expected"),
    [
        ({}, FindingStatus.VERIFIED),
        ({"reproducible": False}, FindingStatus.REJECTED),
        ({"expected_behavior": True}, FindingStatus.REJECTED),
        ({"proves_security_impact": False}, FindingStatus.REJECTED),
        ({"evidence_ids": ()}, FindingStatus.REJECTED),
        ({"requires_destructive_testing": True}, FindingStatus.NEEDS_MANUAL_REVIEW),
    ],
)
def test_verification_verdict_is_computed_not_asserted(
    override: dict[str, object],
    expected: FindingStatus,
) -> None:
    assert verification_verdict(outcome(**override)) is expected


def test_promotion_creates_a_finding_only_when_verification_succeeds() -> None:
    lead, finding = promote_to_finding(make_lead(), outcome(), now=NOW)

    assert lead.status is LeadStatus.VERIFIED
    assert finding is not None
    assert finding.status is FindingStatus.VERIFIED
    assert finding.evidence_ids == EVIDENCE
    assert finding.id in lead.related_findings


def test_promotion_without_evidence_cannot_produce_a_finding() -> None:
    lead, finding = promote_to_finding(make_lead(), outcome(evidence_ids=()), now=NOW)

    assert finding is None
    assert lead.status is LeadStatus.REJECTED


def test_a_result_needing_destructive_proof_becomes_a_human_decision() -> None:
    lead, finding = promote_to_finding(
        make_lead(), outcome(requires_destructive_testing=True), now=NOW
    )

    assert finding is None
    assert lead.status is LeadStatus.NEEDS_APPROVAL
    assert lead.blocked_reason == "requires_manual_review"
