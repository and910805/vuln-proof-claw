"""Immutable evidence metadata and raw-content records."""

from __future__ import annotations

import re
from collections.abc import Mapping
from dataclasses import dataclass
from datetime import datetime

from vuln_proof_claw.domain.errors import DomainValidationError
from vuln_proof_claw.domain.identifiers import (
    ActionId,
    ApprovalId,
    EngagementId,
    EvidenceId,
)
from vuln_proof_claw.evidence.canonical import freeze_canonical

_SHA256 = re.compile(r"^[a-f0-9]{64}$")


def _require_text(value: str, name: str) -> None:
    if not value.strip():
        raise DomainValidationError(f"{name} must not be empty")


@dataclass(frozen=True, slots=True)
class EvidenceMetadata:
    """Canonical metadata committed into an evidence digest."""

    evidence_id: EvidenceId
    engagement_id: EngagementId
    action_id: ActionId
    tool_name: str
    tool_version: str
    normalized_parameters: Mapping[str, object]
    captured_at: datetime
    duration_ms: int
    worker_image: str
    environment: Mapping[str, object]
    scope_decision: str
    approval_id: ApprovalId | None = None
    media_type: str = "application/octet-stream"

    def __post_init__(self) -> None:
        _require_text(self.tool_name, "tool_name")
        _require_text(self.tool_version, "tool_version")
        _require_text(self.worker_image, "worker_image")
        _require_text(self.scope_decision, "scope_decision")
        _require_text(self.media_type, "media_type")
        if self.captured_at.tzinfo is None or self.captured_at.utcoffset() is None:
            raise DomainValidationError("captured_at must be timezone-aware")
        if self.duration_ms < 0:
            raise DomainValidationError("duration_ms must not be negative")
        parameters = freeze_canonical(self.normalized_parameters)
        environment = freeze_canonical(self.environment)
        if not isinstance(parameters, Mapping) or not isinstance(environment, Mapping):
            raise DomainValidationError("parameters and environment must be canonical objects")
        object.__setattr__(self, "normalized_parameters", parameters)
        object.__setattr__(self, "environment", environment)

    def as_canonical_mapping(self) -> Mapping[str, object]:
        """Return all metadata fields that are committed into the digest."""
        return {
            "action_id": self.action_id,
            "approval_id": self.approval_id,
            "captured_at": self.captured_at,
            "duration_ms": self.duration_ms,
            "engagement_id": self.engagement_id,
            "environment": self.environment,
            "evidence_id": self.evidence_id,
            "media_type": self.media_type,
            "normalized_parameters": self.normalized_parameters,
            "scope_decision": self.scope_decision,
            "tool_name": self.tool_name,
            "tool_version": self.tool_version,
            "worker_image": self.worker_image,
        }


@dataclass(frozen=True, slots=True)
class EvidenceRecord:
    """Raw evidence plus its tamper-evident chain fields."""

    metadata: EvidenceMetadata
    raw_content: bytes
    previous_digest: str | None
    digest: str

    def __post_init__(self) -> None:
        object.__setattr__(self, "raw_content", bytes(self.raw_content))
        if self.previous_digest is not None and not _SHA256.fullmatch(self.previous_digest):
            raise DomainValidationError("previous_digest must be a lowercase SHA-256 digest")
        if not _SHA256.fullmatch(self.digest):
            raise DomainValidationError("digest must be a lowercase SHA-256 digest")
