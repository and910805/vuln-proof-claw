"""Tests for the in-memory raw evidence store and index contract."""

from __future__ import annotations

from dataclasses import replace
from datetime import UTC, datetime

import pytest

from vuln_proof_claw.config.redaction import redact
from vuln_proof_claw.domain.identifiers import (
    ActionId,
    EngagementId,
    EvidenceId,
)
from vuln_proof_claw.evidence.hash_chain import append_to_chain, verify_chain
from vuln_proof_claw.evidence.models import EvidenceMetadata
from vuln_proof_claw.evidence.store import (
    DuplicateEvidenceError,
    EvidenceIndex,
    EvidenceStoreError,
    InMemoryEvidenceStore,
    InvalidEvidenceError,
)

NOW = datetime(2026, 7, 30, 12, 0, tzinfo=UTC)


def metadata(evidence_number: int, engagement_number: int = 1) -> EvidenceMetadata:
    return EvidenceMetadata(
        evidence_id=EvidenceId(f"00000000-0000-7000-8000-{evidence_number:012d}"),
        engagement_id=EngagementId(
            f"00000000-0000-7000-8000-{engagement_number:012d}"
        ),
        action_id=ActionId("00000000-0000-7000-8000-000000000200"),
        tool_name="http-client",
        tool_version="1.0.0",
        normalized_parameters={"method": "GET"},
        captured_at=NOW,
        duration_ms=10,
        worker_image="worker@sha256:example",
        environment={"runtime": "test"},
        scope_decision="allow",
    )


def test_store_implements_index_contract_and_builds_per_engagement_chains() -> None:
    store = InMemoryEvidenceStore()
    assert isinstance(store, EvidenceIndex)

    first = store.append(metadata(1), b"first")
    second = store.append(metadata(2), b"second")
    other = store.append(metadata(3, engagement_number=2), b"other")

    assert second.previous_digest == first.digest
    assert other.previous_digest is None
    assert verify_chain(store.for_engagement(first.metadata.engagement_id)).valid
    assert verify_chain(store.for_engagement(other.metadata.engagement_id)).valid


def test_duplicate_identifier_is_rejected() -> None:
    store = InMemoryEvidenceStore()
    item = metadata(1)
    store.append(item, b"first")

    with pytest.raises(DuplicateEvidenceError):
        store.append(item, b"duplicate")


def test_add_requires_record_to_extend_current_chain() -> None:
    store = InMemoryEvidenceStore()
    first = store.append(metadata(1), b"first")
    disconnected = append_to_chain(metadata(2), b"second", previous_digest=None)

    with pytest.raises(EvidenceStoreError, match="does not extend"):
        store.add(disconnected)
    assert store.get(first.metadata.evidence_id) == first


def test_add_rejects_a_tampered_external_record() -> None:
    store = InMemoryEvidenceStore()
    first = store.append(metadata(1), b"first")
    second = append_to_chain(metadata(2), b"second", previous_digest=first.digest)

    with pytest.raises(InvalidEvidenceError, match="digest"):
        store.add(replace(second, raw_content=b"tampered"))


def test_report_redaction_does_not_modify_stored_raw_evidence() -> None:
    store = InMemoryEvidenceStore()
    raw = b"Authorization: Bearer header.payload.signature"
    record = store.append(metadata(1), raw)

    report_value = redact(record.raw_content.decode())
    stored = store.get(record.metadata.evidence_id)

    assert "header.payload.signature" not in report_value
    assert stored is not None
    assert stored.raw_content == raw
    assert stored.digest == record.digest


def test_metadata_is_defensively_frozen_before_storage() -> None:
    parameters = {"headers": {"accept": "application/json"}}
    item = replace(metadata(1), normalized_parameters=parameters)
    store = InMemoryEvidenceStore()
    record = store.append(item, b"response")
    parameters["headers"]["accept"] = "text/plain"

    assert verify_chain((record,)).valid
