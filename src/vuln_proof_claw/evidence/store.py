"""Evidence storage contracts and an in-memory implementation."""

from __future__ import annotations

from collections.abc import Sequence
from threading import RLock
from typing import Protocol, runtime_checkable

from vuln_proof_claw.domain.identifiers import EngagementId, EvidenceId
from vuln_proof_claw.evidence.hash_chain import append_to_chain
from vuln_proof_claw.evidence.models import EvidenceMetadata, EvidenceRecord


class EvidenceStoreError(Exception):
    """Base class for expected evidence-store failures."""


class DuplicateEvidenceError(EvidenceStoreError):
    """Raised when an evidence identifier already exists."""


class InvalidEvidenceError(EvidenceStoreError):
    """Raised when imported evidence fails its integrity check."""


@runtime_checkable
class EvidenceIndex(Protocol):
    """Metadata index contract intended for PostgreSQL adapters."""

    def add(self, record: EvidenceRecord) -> None:
        """Index an immutable evidence record."""

    def get(self, evidence_id: EvidenceId) -> EvidenceRecord | None:
        """Return one indexed record."""

    def for_engagement(self, engagement_id: EngagementId) -> Sequence[EvidenceRecord]:
        """Return the ordered evidence chain for an engagement."""


class InMemoryEvidenceStore:
    """Thread-safe raw evidence store for unit tests and local composition."""

    def __init__(self) -> None:
        self._lock = RLock()
        self._records: dict[EvidenceId, EvidenceRecord] = {}
        self._chains: dict[EngagementId, list[EvidenceRecord]] = {}

    def append(self, metadata: EvidenceMetadata, raw_content: bytes) -> EvidenceRecord:
        """Atomically append raw evidence to its engagement chain."""
        with self._lock:
            if metadata.evidence_id in self._records:
                raise DuplicateEvidenceError
            chain = self._chains.setdefault(metadata.engagement_id, [])
            previous_digest = chain[-1].digest if chain else None
            record = append_to_chain(
                metadata,
                raw_content,
                previous_digest=previous_digest,
            )
            self._records[metadata.evidence_id] = record
            chain.append(record)
            return record

    def add(self, record: EvidenceRecord) -> None:
        """Index a prebuilt record only when it extends the current chain."""
        with self._lock:
            if record.metadata.evidence_id in self._records:
                raise DuplicateEvidenceError
            chain = self._chains.setdefault(record.metadata.engagement_id, [])
            expected_previous = chain[-1].digest if chain else None
            if record.previous_digest != expected_previous:
                raise EvidenceStoreError("record does not extend the engagement chain")
            expected_record = append_to_chain(
                record.metadata,
                record.raw_content,
                previous_digest=record.previous_digest,
            )
            if record.digest != expected_record.digest:
                raise InvalidEvidenceError("record digest does not match its metadata and content")
            self._records[record.metadata.evidence_id] = record
            chain.append(record)

    def get(self, evidence_id: EvidenceId) -> EvidenceRecord | None:
        with self._lock:
            return self._records.get(evidence_id)

    def for_engagement(self, engagement_id: EngagementId) -> tuple[EvidenceRecord, ...]:
        with self._lock:
            return tuple(self._chains.get(engagement_id, ()))
