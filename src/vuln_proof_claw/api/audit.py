"""Canonical audit-event recording helpers."""

from __future__ import annotations

from datetime import UTC, datetime

from sqlalchemy.orm import Session

from vuln_proof_claw.domain.identifiers import EngagementId
from vuln_proof_claw.domain.models import AuditEvent
from vuln_proof_claw.evidence.canonical import canonical_json
from vuln_proof_claw.persistence.repositories import AuditEventRepository


def record_audit_event(  # noqa: PLR0913 - explicit fields prevent ambiguous audit records
    session: Session,
    engagement_id: EngagementId,
    event_type: str,
    actor: str,
    payload: dict[str, object],
    *,
    at: datetime | None = None,
) -> None:
    """Append one canonical, immutable event inside the caller's transaction."""
    AuditEventRepository(session).add(
        AuditEvent(
            engagement_id=engagement_id,
            event_type=event_type,
            actor=actor,
            payload=canonical_json(payload),
            created_at=at or datetime.now(UTC),
        )
    )
