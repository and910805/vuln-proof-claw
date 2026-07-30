"""SHA-256 evidence chaining and verification."""

from __future__ import annotations

import hashlib
from collections.abc import Sequence
from dataclasses import dataclass

from vuln_proof_claw.evidence.canonical import canonical_json
from vuln_proof_claw.evidence.models import EvidenceMetadata, EvidenceRecord

_DOMAIN_SEPARATOR = b"vuln-proof-claw:evidence:v1\x00"
_GENESIS_DIGEST = bytes(32)


def compute_digest(
    *,
    previous_digest: str | None,
    canonical_metadata: bytes,
    raw_content: bytes,
) -> str:
    """Hash an unambiguous framing of the previous hash, metadata, and raw bytes."""
    previous = _GENESIS_DIGEST if previous_digest is None else bytes.fromhex(previous_digest)
    metadata_length = len(canonical_metadata).to_bytes(8, "big")
    content_length = len(raw_content).to_bytes(8, "big")
    payload = b"".join(
        (
            _DOMAIN_SEPARATOR,
            previous,
            metadata_length,
            canonical_metadata,
            content_length,
            raw_content,
        )
    )
    return hashlib.sha256(payload).hexdigest()


def append_to_chain(
    metadata: EvidenceMetadata,
    raw_content: bytes,
    *,
    previous_digest: str | None,
) -> EvidenceRecord:
    """Create an immutable record linked to the previous evidence digest."""
    raw = bytes(raw_content)
    digest = compute_digest(
        previous_digest=previous_digest,
        canonical_metadata=canonical_json(metadata.as_canonical_mapping()),
        raw_content=raw,
    )
    return EvidenceRecord(
        metadata=metadata,
        raw_content=raw,
        previous_digest=previous_digest,
        digest=digest,
    )


@dataclass(frozen=True, slots=True)
class ChainVerification:
    """Detailed result identifying the first invalid evidence record."""

    valid: bool
    checked_records: int
    invalid_index: int | None = None
    reason: str | None = None
    expected_digest: str | None = None
    actual_digest: str | None = None


def verify_chain(records: Sequence[EvidenceRecord]) -> ChainVerification:
    """Verify ordering, previous links, and content digests."""
    expected_previous: str | None = None
    seen_ids: set[str] = set()
    for index, record in enumerate(records):
        evidence_id = str(record.metadata.evidence_id)
        if evidence_id in seen_ids:
            return ChainVerification(False, index, index, "duplicate_evidence_id")
        seen_ids.add(evidence_id)
        if record.previous_digest != expected_previous:
            return ChainVerification(False, index, index, "previous_digest_mismatch")
        expected_digest = compute_digest(
            previous_digest=record.previous_digest,
            canonical_metadata=canonical_json(record.metadata.as_canonical_mapping()),
            raw_content=record.raw_content,
        )
        if record.digest != expected_digest:
            return ChainVerification(
                False,
                index,
                index,
                "digest_mismatch",
                expected_digest,
                record.digest,
            )
        expected_previous = record.digest
    return ChainVerification(True, len(records))
