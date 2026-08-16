"""Worker-capture coordinator tests: evidence persistence with a fake runner."""

from __future__ import annotations

import base64
import hashlib
from collections.abc import Generator
from pathlib import Path

import pytest
from sqlalchemy import Engine

from tests.execution.test_lifecycle import NOW, seed_action
from vuln_proof_claw.domain.enums import ActionState
from vuln_proof_claw.domain.identifiers import ActionId
from vuln_proof_claw.evidence.persistence import PersistentEvidenceStore
from vuln_proof_claw.execution.capture_envelope import CaptureEnvelope
from vuln_proof_claw.execution.protocol import WorkerRequest
from vuln_proof_claw.execution.worker_capture import (
    CaptureOutcome,
    WorkerCaptureCoordinator,
    WorkerCaptureError,
)
from vuln_proof_claw.persistence.base import Base
from vuln_proof_claw.persistence.repositories import (
    ActionRepository,
    AuditEventRepository,
    EvidenceRepository,
)
from vuln_proof_claw.persistence.session import create_engine, create_session_factory

BODY = b"<html>hello from the target</html>"


class FakeRunner:
    identity = "fake-worker@sha256:capture"

    def __init__(
        self,
        envelope: CaptureEnvelope | None = None,
        error: Exception | None = None,
    ) -> None:
        self.envelope = envelope
        self.error = error
        self.requests: list[WorkerRequest] = []

    async def run(self, request: WorkerRequest) -> CaptureEnvelope:
        self.requests.append(request)
        if self.error is not None:
            raise self.error
        assert self.envelope is not None
        return self.envelope


def _success_envelope(target: str) -> CaptureEnvelope:
    return CaptureEnvelope(
        status="succeeded",
        status_code=200,
        final_target=target,
        headers=(("content-type", "text/html"),),
        body_base64=base64.b64encode(BODY).decode("ascii"),
        body_sha256=hashlib.sha256(BODY).hexdigest(),
        duration_ms=11,
    )


@pytest.fixture
def engine(tmp_path: Path) -> Generator[Engine, None, None]:
    result = create_engine(f"sqlite:///{tmp_path / 'capture.db'}", pool_pre_ping=False)
    Base.metadata.create_all(result)
    yield result
    result.dispose()


async def test_successful_capture_persists_verifiable_evidence(engine: Engine) -> None:
    engagement, action, _ = seed_action(engine)
    runner = FakeRunner(_success_envelope(action.normalized_target))
    session_factory = create_session_factory(engine)

    with session_factory.begin() as session:
        outcome = await WorkerCaptureCoordinator(session, runner).capture(action.id, at=NOW)

    assert outcome == CaptureOutcome(ActionState.SUCCEEDED, evidence_id=outcome.evidence_id)
    assert outcome.evidence_id is not None

    with session_factory() as session:
        stored_action = ActionRepository(session).get(action.id)
        evidence = EvidenceRepository(session).for_action(action.id)
        verification = PersistentEvidenceStore(session).verify_engagement(engagement.id)
        audit = AuditEventRepository(session).list_for_engagement(engagement.id)
        events = {event.event_type for event in audit}

    assert stored_action is not None
    assert stored_action.entity.state is ActionState.SUCCEEDED
    assert len(evidence) == 1
    assert evidence[0].id == outcome.evidence_id
    assert verification.valid
    assert "worker_capture.succeeded" in events
    # The bound worker request carried the engagement's scoped target.
    assert runner.requests[0].normalized_target == action.normalized_target


async def test_failed_envelope_marks_action_failed_without_evidence(engine: Engine) -> None:
    engagement, action, _ = seed_action(engine)
    runner = FakeRunner(CaptureEnvelope(status="failed", error_code="transport_failure"))
    session_factory = create_session_factory(engine)

    with session_factory.begin() as session:
        outcome = await WorkerCaptureCoordinator(session, runner).capture(action.id, at=NOW)

    assert outcome.action_state is ActionState.FAILED
    assert outcome.error_code == "transport_failure"

    with session_factory() as session:
        stored_action = ActionRepository(session).get(action.id)
        evidence = EvidenceRepository(session).for_action(action.id)
        audit = AuditEventRepository(session).list_for_engagement(engagement.id)
        events = {event.event_type for event in audit}

    assert stored_action is not None
    assert stored_action.entity.state is ActionState.FAILED
    assert evidence == ()
    assert "worker_capture.failed" in events


async def test_runner_failure_fails_closed(engine: Engine) -> None:
    _engagement, action, _ = seed_action(engine)
    runner = FakeRunner(error=RuntimeError("private docker detail"))
    session_factory = create_session_factory(engine)

    with session_factory.begin() as session:
        outcome = await WorkerCaptureCoordinator(session, runner).capture(action.id, at=NOW)

    assert outcome.action_state is ActionState.FAILED
    assert outcome.error_code == "worker_runtime_failure"

    with session_factory() as session:
        stored_action = ActionRepository(session).get(action.id)
    assert stored_action is not None
    assert stored_action.entity.state is ActionState.FAILED


async def test_unknown_action_is_rejected(engine: Engine) -> None:
    seed_action(engine)
    runner = FakeRunner(_success_envelope("https://example.test:443/public"))
    session_factory = create_session_factory(engine)
    with session_factory.begin() as session:
        coordinator = WorkerCaptureCoordinator(session, runner)
        with pytest.raises(WorkerCaptureError, match="action_not_found"):
            await coordinator.capture(ActionId("00000000-0000-7000-8000-0000000000ff"), at=NOW)
