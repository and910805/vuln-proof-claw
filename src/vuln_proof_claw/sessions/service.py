"""Capture, revoke, and guard captured browser authentication sessions.

The service owns the only path through which authentication material enters or
leaves the database. Material is committed once with its size and SHA-256, is
released only to the owning engagement through a usable session, and every
lifecycle event is written to the immutable audit trail without the material or
its secret values ever appearing in a payload.
"""

from __future__ import annotations

import hashlib
from collections.abc import Iterable
from datetime import UTC, datetime

from sqlalchemy.orm import Session

from vuln_proof_claw.audit import record_audit_event
from vuln_proof_claw.domain.errors import DomainValidationError
from vuln_proof_claw.domain.identifiers import AuthSessionId, EngagementId
from vuln_proof_claw.domain.models import AuthenticationSession
from vuln_proof_claw.persistence.repositories import (
    AuthenticationSessionRepository,
    ConcurrentUpdateError,
    EngagementRepository,
    Stored,
)

DEFAULT_MAX_MATERIAL_BYTES = 1 * 1024 * 1024


class AuthenticationSessionError(Exception):
    """Safe, stable failure raised by the authentication-session boundary."""


class AuthenticationSessionService:
    """Transactional lifecycle boundary for captured authentication sessions."""

    def __init__(
        self,
        session: Session,
        *,
        max_material_bytes: int = DEFAULT_MAX_MATERIAL_BYTES,
    ) -> None:
        if max_material_bytes < 1:
            raise ValueError("max_material_bytes must be positive")
        self._session = session
        self._max_material_bytes = max_material_bytes

    def capture(  # noqa: PLR0913 - explicit fields keep captured metadata unambiguous
        self,
        engagement_id: EngagementId,
        *,
        label: str,
        material: bytes,
        secret_key_names: Iterable[str] = (),
        created_by: str,
        expires_at: datetime,
        at: datetime | None = None,
    ) -> Stored[AuthenticationSession]:
        """Persist one captured session for an existing engagement and audit it."""
        timestamp = at or datetime.now(UTC)
        immutable = bytes(material)
        if len(immutable) > self._max_material_bytes:
            raise AuthenticationSessionError("authentication_material_too_large")
        if EngagementRepository(self._session).get(engagement_id) is None:
            raise AuthenticationSessionError("engagement_not_found")

        normalized_names = tuple(sorted({name.strip() for name in secret_key_names}))
        try:
            entity = AuthenticationSession(
                engagement_id=engagement_id,
                label=label,
                digest=hashlib.sha256(immutable).hexdigest(),
                size=len(immutable),
                secret_key_names=normalized_names,
                created_by=created_by,
                created_at=timestamp,
                expires_at=expires_at,
            )
        except DomainValidationError as error:
            raise AuthenticationSessionError(str(error)) from error

        stored = AuthenticationSessionRepository(self._session).add(entity, immutable)
        self._audit(
            engagement_id,
            "auth_session.captured",
            created_by,
            stored.entity,
            {"key_count": len(normalized_names)},
            at=timestamp,
        )
        return stored

    def revoke(
        self,
        engagement_id: EngagementId,
        session_id: AuthSessionId,
        *,
        actor: str,
        at: datetime | None = None,
    ) -> Stored[AuthenticationSession]:
        """Revoke one engagement-owned session, rejecting an already-revoked one."""
        timestamp = at or datetime.now(UTC)
        repository = AuthenticationSessionRepository(self._session)
        stored = self._require_owned(repository, engagement_id, session_id)
        try:
            revoked = stored.entity.revoke(at=timestamp)
        except DomainValidationError as error:
            raise AuthenticationSessionError(str(error)) from error
        try:
            saved = repository.save(revoked, expected_version=stored.version)
        except ConcurrentUpdateError as error:
            raise AuthenticationSessionError("authentication_session_conflict") from error
        self._audit(
            engagement_id,
            "auth_session.revoked",
            actor,
            saved.entity,
            {},
            at=timestamp,
        )
        return saved

    def read_material(
        self,
        engagement_id: EngagementId,
        session_id: AuthSessionId,
        *,
        reader: str,
        at: datetime | None = None,
    ) -> bytes:
        """Release material to a trusted reader only for a usable, owned session."""
        timestamp = at or datetime.now(UTC)
        repository = AuthenticationSessionRepository(self._session)
        stored = self._require_owned(repository, engagement_id, session_id)
        if not stored.entity.is_usable(at=timestamp):
            raise AuthenticationSessionError("authentication_session_not_usable")
        try:
            material = repository.read_material(engagement_id, session_id)
        except ValueError as error:
            raise AuthenticationSessionError("authentication_session_integrity_invalid") from error
        if material is None:
            raise AuthenticationSessionError("authentication_session_not_found")
        self._audit(
            engagement_id,
            "auth_session.material_read",
            reader,
            stored.entity,
            {},
            at=timestamp,
        )
        return material

    def _require_owned(
        self,
        repository: AuthenticationSessionRepository,
        engagement_id: EngagementId,
        session_id: AuthSessionId,
    ) -> Stored[AuthenticationSession]:
        stored = repository.get(session_id)
        if stored is None or stored.entity.engagement_id != engagement_id:
            raise AuthenticationSessionError("authentication_session_not_found")
        return stored

    def _audit(  # noqa: PLR0913 - explicit fields prevent ambiguous audit records
        self,
        engagement_id: EngagementId,
        event_type: str,
        actor: str,
        entity: AuthenticationSession,
        extra: dict[str, object],
        *,
        at: datetime,
    ) -> None:
        record_audit_event(
            self._session,
            engagement_id,
            event_type,
            actor,
            {
                "session_id": entity.id,
                "label": entity.label,
                "digest": entity.digest,
                "size": entity.size,
                "state": entity.state.value,
                **extra,
            },
            at=at,
        )
