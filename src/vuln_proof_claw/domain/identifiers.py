"""Opaque, time-sortable identifiers for domain and tracing records."""

from __future__ import annotations

import secrets
import time
from dataclasses import dataclass
from threading import Lock
from typing import Final, NewType
from uuid import UUID

_MAX_TIMESTAMP_MS: Final = (1 << 48) - 1
_MAX_RANDOM: Final = (1 << 74) - 1
_UUID7_VERSION: Final = 0b0111
_RFC_4122_VARIANT: Final = 0b10


class _Uuid7Generator:
    """Maintain process-local monotonic UUIDv7 state."""

    def __init__(self) -> None:
        self._lock = Lock()
        self._last_timestamp_ms = -1
        self._last_random = -1

    def next_parts(self, timestamp_ms: int) -> tuple[int, int]:
        """Return monotonic UUIDv7 timestamp and random fields."""
        with self._lock:
            effective_timestamp = max(timestamp_ms, self._last_timestamp_ms)
            if effective_timestamp == self._last_timestamp_ms:
                random_bits = self._last_random + 1
                if random_bits > _MAX_RANDOM:
                    effective_timestamp += 1
                    random_bits = secrets.randbits(74)
            else:
                random_bits = secrets.randbits(74)

            if effective_timestamp > _MAX_TIMESTAMP_MS:
                msg = "UUIDv7 timestamp exceeds its 48-bit range"
                raise ValueError(msg)

            self._last_timestamp_ms = effective_timestamp
            self._last_random = random_bits
            return effective_timestamp, random_bits


_generator = _Uuid7Generator()

ProjectId = NewType("ProjectId", str)
EngagementId = NewType("EngagementId", str)
FlowId = NewType("FlowId", str)
TaskId = NewType("TaskId", str)
ActionId = NewType("ActionId", str)
EvidenceId = NewType("EvidenceId", str)
ArtifactId = NewType("ArtifactId", str)
ReportExportId = NewType("ReportExportId", str)
ApprovalId = NewType("ApprovalId", str)
FindingId = NewType("FindingId", str)
AuditEventId = NewType("AuditEventId", str)
WorkerId = NewType("WorkerId", str)


def uuid7(*, timestamp_ms: int | None = None) -> UUID:
    """Generate an RFC 9562 UUIDv7 with monotonic ordering in this process."""
    current_timestamp = time.time_ns() // 1_000_000 if timestamp_ms is None else timestamp_ms
    if not 0 <= current_timestamp <= _MAX_TIMESTAMP_MS:
        msg = "timestamp_ms must fit in the UUIDv7 48-bit timestamp field"
        raise ValueError(msg)

    effective_timestamp, random_bits = _generator.next_parts(current_timestamp)
    random_a = random_bits >> 62
    random_b = random_bits & ((1 << 62) - 1)
    value = (
        (effective_timestamp << 80)
        | (_UUID7_VERSION << 76)
        | (random_a << 64)
        | (_RFC_4122_VARIANT << 62)
        | random_b
    )
    return UUID(int=value)


def new_identifier() -> str:
    """Return an opaque identifier suitable for persistence and log context."""
    return str(uuid7())


def new_project_id() -> ProjectId:
    return ProjectId(new_identifier())


def new_engagement_id() -> EngagementId:
    return EngagementId(new_identifier())


def new_flow_id() -> FlowId:
    return FlowId(new_identifier())


def new_task_id() -> TaskId:
    return TaskId(new_identifier())


def new_action_id() -> ActionId:
    return ActionId(new_identifier())


def new_evidence_id() -> EvidenceId:
    return EvidenceId(new_identifier())


def new_artifact_id() -> ArtifactId:
    return ArtifactId(new_identifier())


def new_report_export_id() -> ReportExportId:
    return ReportExportId(new_identifier())


def new_approval_id() -> ApprovalId:
    return ApprovalId(new_identifier())


def new_finding_id() -> FindingId:
    return FindingId(new_identifier())


def new_audit_event_id() -> AuditEventId:
    return AuditEventId(new_identifier())


def new_worker_id() -> WorkerId:
    return WorkerId(new_identifier())


@dataclass(frozen=True, slots=True)
class ContextIdentifiers:
    """Identifiers propagated across control-plane and worker boundaries."""

    request_id: str | None = None
    project_id: str | None = None
    engagement_id: str | None = None
    flow_id: str | None = None
    task_id: str | None = None
    action_id: str | None = None
    worker_id: str | None = None

    def as_log_context(self) -> dict[str, str]:
        """Return only populated identifiers for structured logging."""
        return {
            field_name: value
            for field_name, value in (
                ("request_id", self.request_id),
                ("project_id", self.project_id),
                ("engagement_id", self.engagement_id),
                ("flow_id", self.flow_id),
                ("task_id", self.task_id),
                ("action_id", self.action_id),
                ("worker_id", self.worker_id),
            )
            if value is not None
        }
