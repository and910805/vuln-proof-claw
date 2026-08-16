"""Browser session-capture coordinator tests with a fake browser runner."""

from __future__ import annotations

import json
from collections.abc import Generator
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
from sqlalchemy import Engine

from vuln_proof_claw.domain.enums import RiskLevel
from vuln_proof_claw.domain.identifiers import EngagementId
from vuln_proof_claw.domain.models import Engagement, Project
from vuln_proof_claw.execution.session_envelope import LoginInstruction, SessionCaptureEnvelope
from vuln_proof_claw.persistence.base import Base
from vuln_proof_claw.persistence.repositories import (
    AuditEventRepository,
    AuthenticationSessionRepository,
    EngagementRepository,
    ProjectRepository,
    ScopeRepository,
)
from vuln_proof_claw.persistence.session import create_engine, create_session_factory
from vuln_proof_claw.policy.scope import EngagementScope
from vuln_proof_claw.sessions.browser_capture import (
    BrowserSessionCaptureCoordinator,
    BrowserSessionCaptureError,
)
from vuln_proof_claw.sessions.service import AuthenticationSessionService

NOW = datetime(2026, 8, 17, 12, 0, tzinfo=UTC)
STORAGE_STATE = {
    "cookies": [{"name": "sessionid", "value": "TOP-SECRET-COOKIE", "domain": "target"}],
    "origins": [
        {"origin": "http://target:8080", "localStorage": [{"name": "token", "value": "SECRET"}]}
    ],
}


def _login(url: str = "http://target:8080/login") -> LoginInstruction:
    return LoginInstruction(
        url=url,
        username="operator",
        password="hunter2",
        username_selector="#u",
        password_selector="#p",
        submit_selector="#go",
    )


def _success_envelope() -> SessionCaptureEnvelope:
    return SessionCaptureEnvelope(
        status="succeeded",
        final_url="http://target:8080/home",
        storage_state_json=json.dumps(STORAGE_STATE, sort_keys=True, separators=(",", ":")),
        cookie_names=("sessionid",),
        storage_keys=("token",),
        duration_ms=42,
    )


class FakeBrowserRunner:
    identity = "fake-browser@sha256:test"

    def __init__(
        self,
        envelope: SessionCaptureEnvelope | None = None,
        error: Exception | None = None,
    ) -> None:
        self.envelope = envelope
        self.error = error
        self.instructions: list[LoginInstruction] = []

    async def run(self, instruction: LoginInstruction) -> SessionCaptureEnvelope:
        self.instructions.append(instruction)
        if self.error is not None:
            raise self.error
        assert self.envelope is not None
        return self.envelope


@pytest.fixture
def engine(tmp_path: Path) -> Generator[Engine, None, None]:
    result = create_engine(f"sqlite:///{tmp_path / 'browser.db'}", pool_pre_ping=False)
    Base.metadata.create_all(result)
    yield result
    result.dispose()


def seed(engine: Engine) -> EngagementId:
    project = Project(name="Browser", created_at=NOW)
    engagement = Engagement(
        project_id=project.id,
        name="Authenticated testing",
        starts_at=NOW - timedelta(hours=1),
        ends_at=NOW + timedelta(days=1),
        maximum_risk=RiskLevel.L2,
        created_at=NOW,
    )
    scope = EngagementScope.create(
        allowed_hostnames=("target",),
        allowed_ports=(8080,),
        allowed_schemes=("http",),
        allowed_paths=("/",),
        valid_from=engagement.starts_at,
        valid_until=engagement.ends_at,
    )
    factory = create_session_factory(engine)
    with factory.begin() as session:
        ProjectRepository(session).add(project)
        EngagementRepository(session).add(engagement)
        ScopeRepository(session).add(engagement.id, scope)
    return engagement.id


async def test_captured_session_is_persisted_without_leaking_material(engine: Engine) -> None:
    engagement_id = seed(engine)
    runner = FakeBrowserRunner(_success_envelope())
    factory = create_session_factory(engine)

    with factory.begin() as session:
        stored = await BrowserSessionCaptureCoordinator(session, runner).capture(
            engagement_id,
            label="authenticated-user",
            login=_login(),
            created_by="operator:test",
            expires_at=NOW + timedelta(hours=8),
            at=NOW,
        )

    with factory.begin() as session:
        material = AuthenticationSessionService(session).read_material(
            engagement_id, stored.entity.id, reader="evidence_reader:test", at=NOW
        )
    assert stored.entity.secret_key_names == ("sessionid", "token")
    assert json.loads(material) == STORAGE_STATE

    with factory() as session:
        events = AuditEventRepository(session).list_for_engagement(engagement_id)
    assert any(event.event_type == "auth_session.captured" for event in events)
    assert all(b"TOP-SECRET-COOKIE" not in event.payload for event in events)


async def test_login_target_outside_scope_is_refused(engine: Engine) -> None:
    engagement_id = seed(engine)
    runner = FakeBrowserRunner(_success_envelope())
    factory = create_session_factory(engine)

    with factory.begin() as session:
        coordinator = BrowserSessionCaptureCoordinator(session, runner)
        with pytest.raises(BrowserSessionCaptureError, match="out_of_scope"):
            await coordinator.capture(
                engagement_id,
                label="bad",
                login=_login("http://evil.test:8080/login"),
                created_by="operator:test",
                expires_at=NOW + timedelta(hours=8),
                at=NOW,
            )

    assert runner.instructions == []
    with factory() as session:
        sessions = AuthenticationSessionRepository(session).list_for_engagement(engagement_id)
    assert sessions == ()


async def test_failed_capture_records_audit_and_persists_nothing(engine: Engine) -> None:
    engagement_id = seed(engine)
    runner = FakeBrowserRunner(SessionCaptureEnvelope(status="failed", error_code="login_failed"))
    factory = create_session_factory(engine)

    with factory.begin() as session:
        coordinator = BrowserSessionCaptureCoordinator(session, runner)
        with pytest.raises(BrowserSessionCaptureError, match="login_failed"):
            await coordinator.capture(
                engagement_id,
                label="attempt",
                login=_login(),
                created_by="operator:test",
                expires_at=NOW + timedelta(hours=8),
                at=NOW,
            )

    with factory() as session:
        sessions = AuthenticationSessionRepository(session).list_for_engagement(engagement_id)
        events = AuditEventRepository(session).list_for_engagement(engagement_id)
    assert sessions == ()
    assert any(event.event_type == "auth_session.capture_failed" for event in events)


async def test_runner_failure_fails_closed(engine: Engine) -> None:
    engagement_id = seed(engine)
    runner = FakeBrowserRunner(error=RuntimeError("private browser detail"))
    factory = create_session_factory(engine)

    with factory.begin() as session:
        coordinator = BrowserSessionCaptureCoordinator(session, runner)
        with pytest.raises(BrowserSessionCaptureError, match="browser_runtime_failure") as caught:
            await coordinator.capture(
                engagement_id,
                label="attempt",
                login=_login(),
                created_by="operator:test",
                expires_at=NOW + timedelta(hours=8),
                at=NOW,
            )
    assert "private browser detail" not in str(caught.value)
