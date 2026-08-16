"""Authentication session service tests over a real SQLite engine."""

from __future__ import annotations

from collections.abc import Generator
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
from sqlalchemy import Engine, update

from vuln_proof_claw.domain.enums import AuthSessionState, RiskLevel
from vuln_proof_claw.domain.identifiers import AuthSessionId, EngagementId
from vuln_proof_claw.domain.models import Engagement, Project
from vuln_proof_claw.persistence.base import Base
from vuln_proof_claw.persistence.models import AuthenticationSessionRecord
from vuln_proof_claw.persistence.repositories import (
    AuditEventRepository,
    AuthenticationSessionRepository,
    EngagementRepository,
    ProjectRepository,
)
from vuln_proof_claw.persistence.session import create_engine, create_session_factory
from vuln_proof_claw.sessions import AuthenticationSessionError, AuthenticationSessionService

NOW = datetime(2026, 8, 16, 12, 0, tzinfo=UTC)
MATERIAL = b'{"cookies": {"sessionid": "TOP-SECRET-COOKIE-VALUE"}}'


@pytest.fixture
def engine(tmp_path: Path) -> Generator[Engine, None, None]:
    result = create_engine(f"sqlite:///{tmp_path / 'sessions.db'}", pool_pre_ping=False)
    Base.metadata.create_all(result)
    yield result
    result.dispose()


def seed_engagement(engine: Engine) -> EngagementId:
    project = Project(name="Auth", created_at=NOW)
    engagement = Engagement(
        project_id=project.id,
        name="Authenticated testing",
        starts_at=NOW - timedelta(hours=1),
        ends_at=NOW + timedelta(days=1),
        maximum_risk=RiskLevel.L2,
        created_at=NOW,
    )
    session_factory = create_session_factory(engine)
    with session_factory.begin() as session:
        ProjectRepository(session).add(project)
        EngagementRepository(session).add(engagement)
    return engagement.id


def _audit_events(engine: Engine, engagement_id: EngagementId) -> list[tuple[str, bytes]]:
    session_factory = create_session_factory(engine)
    with session_factory() as session:
        events = AuditEventRepository(session).list_for_engagement(engagement_id)
    return [(event.event_type, event.payload) for event in events]


def test_capture_persists_metadata_and_audits_without_leaking_material(engine: Engine) -> None:
    engagement_id = seed_engagement(engine)
    session_factory = create_session_factory(engine)
    with session_factory.begin() as session:
        stored = AuthenticationSessionService(session).capture(
            engagement_id,
            label="authenticated-user",
            material=MATERIAL,
            secret_key_names=("sessionid", "sessionid", "csrftoken"),
            created_by="operator:test",
            expires_at=NOW + timedelta(hours=8),
            at=NOW,
        )

    with session_factory() as session:
        listed = AuthenticationSessionRepository(session).list_for_engagement(engagement_id)
    assert stored.entity.state is AuthSessionState.ACTIVE
    assert stored.entity.size == len(MATERIAL)
    assert stored.entity.secret_key_names == ("csrftoken", "sessionid")
    assert len(listed) == 1
    assert listed[0].id == stored.entity.id

    events = _audit_events(engine, engagement_id)
    assert any(event_type == "auth_session.captured" for event_type, _ in events)
    assert all(b"TOP-SECRET-COOKIE-VALUE" not in payload for _, payload in events)


def test_read_material_returns_bytes_for_usable_session_and_audits(engine: Engine) -> None:
    engagement_id = seed_engagement(engine)
    session_factory = create_session_factory(engine)
    with session_factory.begin() as session:
        stored = AuthenticationSessionService(session).capture(
            engagement_id,
            label="authenticated-user",
            material=MATERIAL,
            created_by="operator:test",
            expires_at=NOW + timedelta(hours=8),
            at=NOW,
        )
    with session_factory.begin() as session:
        material = AuthenticationSessionService(session).read_material(
            engagement_id,
            stored.entity.id,
            reader="evidence_reader:test",
            at=NOW + timedelta(hours=1),
        )
    assert material == MATERIAL
    events = _audit_events(engine, engagement_id)
    assert any(event_type == "auth_session.material_read" for event_type, _ in events)
    assert all(b"TOP-SECRET-COOKIE-VALUE" not in payload for _, payload in events)


def test_revoked_session_material_is_not_released(engine: Engine) -> None:
    engagement_id = seed_engagement(engine)
    session_factory = create_session_factory(engine)
    with session_factory.begin() as session:
        stored = AuthenticationSessionService(session).capture(
            engagement_id,
            label="authenticated-user",
            material=MATERIAL,
            created_by="operator:test",
            expires_at=NOW + timedelta(hours=8),
            at=NOW,
        )
    with session_factory.begin() as session:
        AuthenticationSessionService(session).revoke(
            engagement_id,
            stored.entity.id,
            actor="operator:test",
            at=NOW + timedelta(minutes=5),
        )
    with session_factory.begin() as session:
        service = AuthenticationSessionService(session)
        with pytest.raises(AuthenticationSessionError, match="not_usable"):
            service.read_material(
                engagement_id,
                stored.entity.id,
                reader="evidence_reader:test",
                at=NOW + timedelta(hours=1),
            )


def test_expired_session_material_is_not_released(engine: Engine) -> None:
    engagement_id = seed_engagement(engine)
    session_factory = create_session_factory(engine)
    with session_factory.begin() as session:
        stored = AuthenticationSessionService(session).capture(
            engagement_id,
            label="short-lived",
            material=MATERIAL,
            created_by="operator:test",
            expires_at=NOW + timedelta(minutes=30),
            at=NOW,
        )
    with session_factory.begin() as session:
        service = AuthenticationSessionService(session)
        with pytest.raises(AuthenticationSessionError, match="not_usable"):
            service.read_material(
                engagement_id,
                stored.entity.id,
                reader="evidence_reader:test",
                at=NOW + timedelta(hours=1),
            )


def test_double_revoke_is_rejected(engine: Engine) -> None:
    engagement_id = seed_engagement(engine)
    session_factory = create_session_factory(engine)
    with session_factory.begin() as session:
        stored = AuthenticationSessionService(session).capture(
            engagement_id,
            label="authenticated-user",
            material=MATERIAL,
            created_by="operator:test",
            expires_at=NOW + timedelta(hours=8),
            at=NOW,
        )
    with session_factory.begin() as session:
        AuthenticationSessionService(session).revoke(
            engagement_id, stored.entity.id, actor="operator:test", at=NOW
        )
    with session_factory.begin() as session:
        service = AuthenticationSessionService(session)
        with pytest.raises(AuthenticationSessionError, match="only active sessions"):
            service.revoke(engagement_id, stored.entity.id, actor="operator:test", at=NOW)


def test_capture_requires_an_existing_engagement(engine: Engine) -> None:
    session_factory = create_session_factory(engine)
    with session_factory.begin() as session:
        service = AuthenticationSessionService(session)
        with pytest.raises(AuthenticationSessionError, match="engagement_not_found"):
            service.capture(
                EngagementId("01a00ac9-0000-7000-8000-0000000000ff"),
                label="orphan",
                material=MATERIAL,
                created_by="operator:test",
                expires_at=NOW + timedelta(hours=8),
                at=NOW,
            )


def test_oversized_material_is_rejected(engine: Engine) -> None:
    engagement_id = seed_engagement(engine)
    session_factory = create_session_factory(engine)
    with session_factory.begin() as session:
        service = AuthenticationSessionService(session, max_material_bytes=16)
        with pytest.raises(AuthenticationSessionError, match="too_large"):
            service.capture(
                engagement_id,
                label="big",
                material=MATERIAL,
                created_by="operator:test",
                expires_at=NOW + timedelta(hours=8),
                at=NOW,
            )


def test_cross_engagement_access_is_refused(engine: Engine) -> None:
    engagement_id = seed_engagement(engine)
    other_engagement = seed_engagement(engine)
    session_factory = create_session_factory(engine)
    with session_factory.begin() as session:
        stored = AuthenticationSessionService(session).capture(
            engagement_id,
            label="authenticated-user",
            material=MATERIAL,
            created_by="operator:test",
            expires_at=NOW + timedelta(hours=8),
            at=NOW,
        )
    with session_factory.begin() as session:
        service = AuthenticationSessionService(session)
        with pytest.raises(AuthenticationSessionError, match="not_found"):
            service.read_material(
                other_engagement,
                stored.entity.id,
                reader="evidence_reader:test",
                at=NOW + timedelta(hours=1),
            )


def test_tampered_material_fails_closed(engine: Engine) -> None:
    engagement_id = seed_engagement(engine)
    session_factory = create_session_factory(engine)
    with session_factory.begin() as session:
        stored = AuthenticationSessionService(session).capture(
            engagement_id,
            label="authenticated-user",
            material=MATERIAL,
            created_by="operator:test",
            expires_at=NOW + timedelta(hours=8),
            at=NOW,
        )
    with session_factory.begin() as session:
        session.execute(
            update(AuthenticationSessionRecord)
            .where(AuthenticationSessionRecord.id == stored.entity.id)
            .values(material=MATERIAL + b"tampered")
        )
    with session_factory.begin() as session:
        service = AuthenticationSessionService(session)
        with pytest.raises(AuthenticationSessionError, match="integrity_invalid"):
            service.read_material(
                engagement_id,
                AuthSessionId(stored.entity.id),
                reader="evidence_reader:test",
                at=NOW + timedelta(hours=1),
            )
