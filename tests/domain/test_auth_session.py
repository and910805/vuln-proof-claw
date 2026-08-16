"""Validation and lifecycle tests for the authentication session model."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest

from vuln_proof_claw.domain.enums import AuthSessionState
from vuln_proof_claw.domain.errors import DomainValidationError
from vuln_proof_claw.domain.identifiers import EngagementId
from vuln_proof_claw.domain.models import AuthenticationSession

NOW = datetime(2026, 8, 16, 12, 0, tzinfo=UTC)
DIGEST = "a" * 64


def _session(**overrides: object) -> AuthenticationSession:
    values: dict[str, object] = {
        "engagement_id": EngagementId("01a00ac9-0000-7000-8000-000000000001"),
        "label": "authenticated-user",
        "digest": DIGEST,
        "size": 128,
        "created_by": "operator:test",
        "created_at": NOW,
        "expires_at": NOW + timedelta(hours=8),
        "secret_key_names": ("csrftoken", "sessionid"),
    }
    values.update(overrides)
    return AuthenticationSession(**values)  # type: ignore[arg-type]


def test_active_session_is_usable_only_within_its_window() -> None:
    session = _session()
    assert session.state is AuthSessionState.ACTIVE
    assert session.is_usable(at=NOW)
    assert session.is_usable(at=NOW + timedelta(hours=7))
    assert not session.is_usable(at=NOW - timedelta(seconds=1))
    assert not session.is_usable(at=NOW + timedelta(hours=8))


def test_revoke_produces_a_revoked_copy_and_blocks_use() -> None:
    session = _session()
    revoked = session.revoke(at=NOW + timedelta(hours=1))
    assert session.state is AuthSessionState.ACTIVE
    assert revoked.state is AuthSessionState.REVOKED
    assert revoked.revoked_at == NOW + timedelta(hours=1)
    assert not revoked.is_usable(at=NOW + timedelta(hours=2))


def test_revoking_a_revoked_session_is_rejected() -> None:
    revoked = _session().revoke(at=NOW)
    with pytest.raises(DomainValidationError, match="only active sessions"):
        revoked.revoke(at=NOW + timedelta(hours=1))


def test_expiry_must_be_after_creation() -> None:
    with pytest.raises(DomainValidationError, match="expires_at must be later"):
        _session(expires_at=NOW)


def test_negative_size_is_rejected() -> None:
    with pytest.raises(DomainValidationError, match="size must not be negative"):
        _session(size=-1)


def test_active_session_must_not_carry_revoked_at() -> None:
    with pytest.raises(DomainValidationError, match="active sessions must not"):
        _session(revoked_at=NOW)


def test_revoked_state_requires_revoked_at() -> None:
    with pytest.raises(DomainValidationError, match="revoked sessions require"):
        _session(state=AuthSessionState.REVOKED)


def test_non_sha256_digest_is_rejected() -> None:
    with pytest.raises(DomainValidationError, match="digest"):
        _session(digest="not-a-digest")
