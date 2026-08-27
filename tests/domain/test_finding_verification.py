"""Tests for the control-evidence requirement on verified findings."""

from __future__ import annotations

from datetime import UTC, datetime

import pytest

from vuln_proof_claw.domain.enums import (
    ArtifactKind,
    FindingSeverity,
    FindingStatus,
    VerificationMethod,
)
from vuln_proof_claw.domain.errors import DomainValidationError
from vuln_proof_claw.domain.finding import requires_control_evidence, review_finding
from vuln_proof_claw.domain.identifiers import (
    EvidenceId,
    new_engagement_id,
    new_evidence_id,
)
from vuln_proof_claw.domain.models import Finding

NOW = datetime(2026, 8, 26, 12, 0, tzinfo=UTC)
ENGAGEMENT = new_engagement_id()
PAYLOAD: tuple[EvidenceId, ...] = (new_evidence_id(),)
CONTROL: tuple[EvidenceId, ...] = (new_evidence_id(),)


def finding(**overrides: object) -> Finding:
    defaults: dict[str, object] = {
        "engagement_id": ENGAGEMENT,
        "title": "Unauthenticated arbitrary file read",
        "vulnerability_class": "path_traversal",
        "affected_target": "https://example.test/wp-admin/admin-ajax.php",
        "evidence_ids": PAYLOAD,
        "status": FindingStatus.PENDING_VERIFICATION,
        "created_at": NOW,
    }
    defaults.update(overrides)
    return Finding(**defaults)  # type: ignore[arg-type]


def test_baseline_and_negative_control_are_control_artifacts() -> None:
    assert ArtifactKind.BASELINE.is_control
    assert ArtifactKind.NEGATIVE_CONTROL.is_control
    assert not ArtifactKind.PROOF_OF_CONCEPT.is_control


def test_an_observation_can_be_verified_without_a_control() -> None:
    reviewed = review_finding(
        finding(severity=FindingSeverity.LOW),
        FindingStatus.VERIFIED,
    )
    assert reviewed.status is FindingStatus.VERIFIED


def test_a_differential_claim_needs_a_control() -> None:
    candidate = finding(
        severity=FindingSeverity.MEDIUM,
        verification_method=VerificationMethod.DIFFERENTIAL,
    )
    assert requires_control_evidence(candidate)
    with pytest.raises(DomainValidationError, match="control evidence"):
        review_finding(candidate, FindingStatus.VERIFIED)


def test_a_differential_candidate_may_exist_before_its_control_is_captured() -> None:
    # Create-then-verify: the control capture does not exist yet, and refusing
    # the candidate here would make the differential workflow unreachable.
    candidate = finding(verification_method=VerificationMethod.DIFFERENTIAL)
    assert candidate.status is FindingStatus.PENDING_VERIFICATION
    assert candidate.control_evidence_ids == ()


def test_no_writer_can_mint_a_verified_differential_finding_without_a_control() -> None:
    # The rule lives in __post_init__, so direct construction is bound too.
    with pytest.raises(DomainValidationError, match="control evidence"):
        finding(
            status=FindingStatus.VERIFIED,
            verification_method=VerificationMethod.DIFFERENTIAL,
        )


def test_a_differential_claim_with_a_control_verifies() -> None:
    candidate = finding(
        severity=FindingSeverity.MEDIUM,
        verification_method=VerificationMethod.DIFFERENTIAL,
        control_evidence_ids=CONTROL,
    )
    assert review_finding(candidate, FindingStatus.VERIFIED).status is FindingStatus.VERIFIED


@pytest.mark.parametrize("severity", [FindingSeverity.HIGH, FindingSeverity.CRITICAL])
def test_high_severity_must_state_a_verification_method(severity: FindingSeverity) -> None:
    # Rewritten: this used to assert that HIGH forced DIFFERENTIAL. The rule was
    # narrowed -- HIGH no longer owes a comparison, it owes a stated basis.
    with pytest.raises(DomainValidationError, match="must state a verification method"):
        finding(severity=severity)


@pytest.mark.parametrize("severity", [FindingSeverity.HIGH, FindingSeverity.CRITICAL])
def test_a_high_observation_verifies_without_a_control(severity: FindingSeverity) -> None:
    # A cookie either carries HttpOnly or it does not; there is no baseline to
    # hold that against, so demanding a control here would be incoherent.
    candidate = finding(severity=severity, verification_method=VerificationMethod.OBSERVED)
    assert not requires_control_evidence(candidate)
    reviewed = review_finding(candidate, FindingStatus.VERIFIED)
    assert reviewed.status is FindingStatus.VERIFIED
    assert reviewed.control_evidence_ids == ()


def test_critical_with_differential_control_verifies() -> None:
    candidate = finding(
        severity=FindingSeverity.CRITICAL,
        verification_method=VerificationMethod.DIFFERENTIAL,
        control_evidence_ids=CONTROL,
    )
    assert review_finding(candidate, FindingStatus.VERIFIED).status is FindingStatus.VERIFIED


def test_verification_still_needs_at_least_one_payload_record() -> None:
    with pytest.raises(DomainValidationError, match="at least one evidence"):
        review_finding(finding(evidence_ids=()), FindingStatus.VERIFIED)


def test_one_record_cannot_be_both_payload_and_control() -> None:
    with pytest.raises(DomainValidationError, match="payload and control"):
        finding(control_evidence_ids=PAYLOAD)


@pytest.mark.parametrize("value", ["CWE-79", "CWE-1", "CWE-12345"])
def test_well_formed_cwe_is_accepted(value: str) -> None:
    assert finding(cwe_id=value).cwe_id == value


@pytest.mark.parametrize("value", ["79", "cwe-79", "CWE79", "CWE-", "CWE-abc", "CWE-123456"])
def test_malformed_cwe_is_rejected(value: str) -> None:
    with pytest.raises(DomainValidationError, match="cwe_id"):
        finding(cwe_id=value)


def test_dedupe_key_ignores_target_case_and_a_trailing_slash() -> None:
    first = finding(cwe_id="CWE-22", affected_target="https://Example.test/App/")
    second = finding(cwe_id="CWE-22", affected_target="https://example.test/App")
    assert first.dedupe_key == second.dedupe_key


def test_dedupe_key_normalises_class_case() -> None:
    upper = finding(vulnerability_class="Path_Traversal")
    lower = finding(vulnerability_class="path_traversal")
    assert upper.dedupe_key == lower.dedupe_key


def test_dedupe_key_separates_different_classes() -> None:
    traversal = finding(vulnerability_class="path_traversal")
    injection = finding(vulnerability_class="command_injection")
    assert traversal.dedupe_key != injection.dedupe_key


def test_a_non_review_status_is_refused() -> None:
    with pytest.raises(DomainValidationError, match="review status"):
        review_finding(finding(), FindingStatus.CANDIDATE)


def test_reviewing_to_the_same_status_is_a_no_op() -> None:
    candidate = finding(status=FindingStatus.REJECTED)
    assert review_finding(candidate, FindingStatus.REJECTED) is candidate


def test_a_verified_finding_cannot_slip_back_to_pending() -> None:
    # Reopening has to go through manual review so the reversal is visible.
    verified = finding(severity=FindingSeverity.LOW, status=FindingStatus.VERIFIED)
    with pytest.raises(DomainValidationError, match="manual review"):
        review_finding(verified, FindingStatus.PENDING_VERIFICATION)


def test_a_rejected_finding_cannot_slip_back_to_pending() -> None:
    rejected = finding(status=FindingStatus.REJECTED)
    with pytest.raises(DomainValidationError, match="manual review"):
        review_finding(rejected, FindingStatus.PENDING_VERIFICATION)


def test_a_verified_finding_can_be_reopened_for_manual_review() -> None:
    verified = finding(severity=FindingSeverity.LOW, status=FindingStatus.VERIFIED)
    reopened = review_finding(verified, FindingStatus.NEEDS_MANUAL_REVIEW)
    assert reopened.status is FindingStatus.NEEDS_MANUAL_REVIEW


def test_rejecting_needs_no_control_even_at_high_severity() -> None:
    # The control requirement guards a claim, not a dismissal.
    candidate = finding(
        severity=FindingSeverity.CRITICAL,
        verification_method=VerificationMethod.DIFFERENTIAL,
    )
    assert review_finding(candidate, FindingStatus.REJECTED).status is FindingStatus.REJECTED


def test_an_informational_observation_needs_no_control() -> None:
    candidate = finding(severity=FindingSeverity.INFORMATIONAL)
    assert not requires_control_evidence(candidate)
    assert review_finding(candidate, FindingStatus.VERIFIED).status is FindingStatus.VERIFIED
