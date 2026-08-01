"""Transactional persistence for raw, tamper-evident evidence chains."""

from __future__ import annotations

from datetime import UTC, datetime

from sqlalchemy import select
from sqlalchemy.orm import Session

from vuln_proof_claw.domain.identifiers import ActionId, EvidenceId
from vuln_proof_claw.domain.models import Evidence
from vuln_proof_claw.evidence.canonical import canonical_json
from vuln_proof_claw.evidence.hash_chain import (
    ChainVerification,
    append_to_chain,
    compute_digest,
)
from vuln_proof_claw.evidence.models import EvidenceMetadata, EvidenceRecord
from vuln_proof_claw.evidence.store import (
    DuplicateEvidenceError,
    EvidenceStoreError,
    InvalidEvidenceError,
)
from vuln_proof_claw.persistence.models import (
    ActionRecord,
    EngagementRecord,
    EvidencePayloadRecord,
)
from vuln_proof_claw.persistence.models import EvidenceRecord as EvidenceMetadataRecord

DEFAULT_MAX_RAW_EVIDENCE_BYTES = 10 * 1024 * 1024


def _utc(value: datetime) -> datetime:
    if value.tzinfo is None:
        return value.replace(tzinfo=UTC)
    return value.astimezone(UTC)


class EvidenceTooLargeError(EvidenceStoreError):
    """Raised before oversized raw evidence can enter a transaction."""


class PersistentEvidenceStore:
    """Append and verify per-engagement evidence chains in one database transaction."""

    def __init__(
        self,
        session: Session,
        *,
        max_raw_bytes: int = DEFAULT_MAX_RAW_EVIDENCE_BYTES,
    ) -> None:
        if max_raw_bytes < 1:
            raise ValueError("max_raw_bytes must be positive")
        self._session = session
        self._max_raw_bytes = max_raw_bytes

    def append(self, metadata: EvidenceMetadata, raw_content: bytes) -> EvidenceRecord:
        """Append evidence after locking and validating its engagement boundary."""
        raw = bytes(raw_content)
        if len(raw) > self._max_raw_bytes:
            raise EvidenceTooLargeError(
                f"raw evidence exceeds {self._max_raw_bytes} byte limit"
            )
        if self._session.get(EvidenceMetadataRecord, metadata.evidence_id) is not None:
            raise DuplicateEvidenceError

        action = self._session.get(ActionRecord, metadata.action_id)
        if action is None or action.engagement_id != metadata.engagement_id:
            raise InvalidEvidenceError("action is not part of the evidence engagement")

        engagement = self._session.scalar(
            select(EngagementRecord)
            .where(EngagementRecord.id == metadata.engagement_id)
            .with_for_update()
        )
        if engagement is None:
            raise InvalidEvidenceError("evidence engagement does not exist")

        latest = self._session.execute(
            select(EvidencePayloadRecord, EvidenceMetadataRecord)
            .join(
                EvidenceMetadataRecord,
                EvidenceMetadataRecord.id == EvidencePayloadRecord.evidence_id,
            )
            .where(EvidencePayloadRecord.engagement_id == metadata.engagement_id)
            .order_by(EvidencePayloadRecord.chain_index.desc())
            .limit(1)
        ).one_or_none()
        chain_index = 0 if latest is None else latest[0].chain_index + 1
        previous_digest = None if latest is None else latest[1].digest
        record = append_to_chain(metadata, raw, previous_digest=previous_digest)
        canonical_metadata = canonical_json(metadata.as_canonical_mapping())

        self._session.add(
            EvidenceMetadataRecord(
                id=metadata.evidence_id,
                action_id=metadata.action_id,
                tool_name=metadata.tool_name,
                tool_version=metadata.tool_version,
                digest=record.digest,
                previous_digest=record.previous_digest,
                captured_at=metadata.captured_at,
            )
        )
        self._session.add(
            EvidencePayloadRecord(
                evidence_id=metadata.evidence_id,
                engagement_id=metadata.engagement_id,
                chain_index=chain_index,
                canonical_metadata=canonical_metadata,
                raw_content=raw,
                raw_size=len(raw),
            )
        )
        self._session.flush()
        return record

    def read_raw(self, evidence_id: str) -> bytes | None:
        """Return raw bytes to trusted internal callers; no public API exposes this method."""
        payload = self._session.get(EvidencePayloadRecord, evidence_id)
        return None if payload is None else bytes(payload.raw_content)

    def verify_engagement(self, engagement_id: str) -> ChainVerification:
        """Recompute every link from persisted canonical metadata and raw bytes."""
        rows = tuple(
            self._session.execute(
                select(EvidencePayloadRecord, EvidenceMetadataRecord)
                .join(
                    EvidenceMetadataRecord,
                    EvidenceMetadataRecord.id == EvidencePayloadRecord.evidence_id,
                )
                .where(EvidencePayloadRecord.engagement_id == engagement_id)
                .order_by(EvidencePayloadRecord.chain_index)
            )
        )
        expected_previous: str | None = None
        for index, (payload, metadata) in enumerate(rows):
            if payload.chain_index != index:
                return ChainVerification(False, index, index, "chain_index_mismatch")
            if metadata.previous_digest != expected_previous:
                return ChainVerification(False, index, index, "previous_digest_mismatch")
            if payload.raw_size != len(payload.raw_content):
                return ChainVerification(False, index, index, "raw_size_mismatch")
            expected_digest = compute_digest(
                previous_digest=metadata.previous_digest,
                canonical_metadata=bytes(payload.canonical_metadata),
                raw_content=bytes(payload.raw_content),
            )
            if metadata.digest != expected_digest:
                return ChainVerification(
                    False,
                    index,
                    index,
                    "digest_mismatch",
                    expected_digest,
                    metadata.digest,
                )
            expected_previous = metadata.digest
        return ChainVerification(True, len(rows))

    def metadata_for_engagement(self, engagement_id: str) -> tuple[Evidence, ...]:
        """List public evidence metadata without materializing raw payloads."""
        rows = self._session.scalars(
            select(EvidenceMetadataRecord)
            .join(
                EvidencePayloadRecord,
                EvidencePayloadRecord.evidence_id == EvidenceMetadataRecord.id,
            )
            .where(EvidencePayloadRecord.engagement_id == engagement_id)
            .order_by(EvidencePayloadRecord.chain_index)
        )
        return tuple(
            Evidence(
                id=EvidenceId(row.id),
                action_id=ActionId(row.action_id),
                tool_name=row.tool_name,
                tool_version=row.tool_version,
                digest=row.digest,
                previous_digest=row.previous_digest,
                captured_at=_utc(row.captured_at),
            )
            for row in rows
        )
