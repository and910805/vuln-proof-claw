"""Tests for evidence hashing and chain verification."""

from __future__ import annotations

from dataclasses import replace
from datetime import UTC, datetime

from vuln_proof_claw.domain.identifiers import (
    ActionId,
    EngagementId,
    EvidenceId,
)
from vuln_proof_claw.evidence.hash_chain import append_to_chain, verify_chain
from vuln_proof_claw.evidence.models import EvidenceMetadata, EvidenceRecord

NOW = datetime(2026, 7, 30, 12, 0, tzinfo=UTC)


def metadata(number: int) -> EvidenceMetadata:
    return EvidenceMetadata(
        evidence_id=EvidenceId(f"00000000-0000-7000-8000-{number:012d}"),
        engagement_id=EngagementId("00000000-0000-7000-8000-000000000100"),
        action_id=ActionId("00000000-0000-7000-8000-000000000200"),
        tool_name="http-client",
        tool_version="1.0.0",
        normalized_parameters={"method": "GET", "sequence": number},
        captured_at=NOW,
        duration_ms=25,
        worker_image="worker@sha256:example",
        environment={"runtime": "test"},
        scope_decision="allow",
        media_type="application/http",
    )


def make_chain() -> tuple[EvidenceRecord, EvidenceRecord, EvidenceRecord]:
    first = append_to_chain(metadata(1), b"first response", previous_digest=None)
    second = append_to_chain(metadata(2), b"second response", previous_digest=first.digest)
    third = append_to_chain(metadata(3), b"third response", previous_digest=second.digest)
    return first, second, third


def test_digest_has_a_stable_test_vector() -> None:
    record = append_to_chain(metadata(1), b"first response", previous_digest=None)

    assert record.digest == "3f13187dcfd190ab508cc7491cbab68364ab4fb986322dfa688b1fecd5a8c877"


def test_complete_chain_verifies() -> None:
    result = verify_chain(make_chain())

    assert result.valid
    assert result.checked_records == 3
    assert result.invalid_index is None


def test_raw_content_tampering_identifies_first_invalid_record() -> None:
    first, second, third = make_chain()
    tampered = replace(second, raw_content=b"modified response")

    result = verify_chain((first, tampered, third))

    assert not result.valid
    assert result.invalid_index == 1
    assert result.reason == "digest_mismatch"
    assert result.expected_digest != result.actual_digest


def test_metadata_tampering_is_detected() -> None:
    first, second, third = make_chain()
    changed_metadata = replace(second.metadata, worker_image="different-image")

    result = verify_chain((first, replace(second, metadata=changed_metadata), third))

    assert not result.valid
    assert result.invalid_index == 1
    assert result.reason == "digest_mismatch"


def test_missing_or_reordered_record_breaks_previous_link() -> None:
    first, _second, third = make_chain()

    result = verify_chain((first, third))

    assert not result.valid
    assert result.invalid_index == 1
    assert result.reason == "previous_digest_mismatch"


def test_duplicate_evidence_identifier_is_rejected() -> None:
    first, second, _third = make_chain()
    duplicate_metadata = replace(second.metadata, evidence_id=first.metadata.evidence_id)
    duplicate = append_to_chain(
        duplicate_metadata,
        second.raw_content,
        previous_digest=first.digest,
    )

    result = verify_chain((first, duplicate))

    assert not result.valid
    assert result.invalid_index == 1
    assert result.reason == "duplicate_evidence_id"
