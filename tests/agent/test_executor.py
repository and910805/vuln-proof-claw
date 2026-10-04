"""End-to-end tests for the controller driving the real evidence-capture path."""

from __future__ import annotations

from collections.abc import Generator
from dataclasses import dataclass, field
from pathlib import Path

import pytest
from sqlalchemy import Engine, select

from tests.agent.support import (
    NOW,
    TARGET_HOST,
    TARGET_URL,
    build_engine,
    seed_engagement,
    seed_lead,
    seed_mission,
    session_factory,
)
from vuln_proof_claw.agent.controller import MissionController
from vuln_proof_claw.agent.executor import HttpCaptureExecutor, RefusingExecutor
from vuln_proof_claw.agent.planner import DeterministicPlanner
from vuln_proof_claw.domain.enums import ActionState, LeadStatus, RiskLevel
from vuln_proof_claw.domain.identifiers import LeadId, MissionId
from vuln_proof_claw.domain.models import Action
from vuln_proof_claw.execution.http_capture import (
    CaptureTransportError,
    HttpCaptureLimits,
    HttpCaptureRequest,
    HttpCaptureResponse,
)
from vuln_proof_claw.persistence.autonomous_repositories import (
    LeadRepository,
    ObservationRepository,
)
from vuln_proof_claw.persistence.models import EvidenceRecord
from vuln_proof_claw.persistence.repositories import ActionRepository
from vuln_proof_claw.policy.decision import DecisionKind, PolicyDecision
from vuln_proof_claw.policy.scope import normalize_target


@dataclass
class StubTransport:
    """A transport that returns a fixed bounded response without network access."""

    status_code: int = 200
    body: bytes = b"<html>orders</html>"
    error: CaptureTransportError | None = None
    requests: list[HttpCaptureRequest] = field(default_factory=list)

    @property
    def identity(self) -> str:
        return "stub-transport/v1"

    def send(
        self,
        request: HttpCaptureRequest,
        limits: HttpCaptureLimits,
    ) -> HttpCaptureResponse:
        self.requests.append(request)
        if self.error is not None:
            raise self.error
        return HttpCaptureResponse(
            status_code=self.status_code,
            final_target=request.target,
            headers=(("content-type", "text/html"),),
            body=self.body,
            duration_ms=12,
        )


@pytest.fixture
def engine(tmp_path: Path) -> Generator[Engine, None, None]:
    yield from build_engine(tmp_path / "executor.db")


def test_refusing_executor_never_performs_anything() -> None:
    action = Action(
        engagement_id="e",  # type: ignore[arg-type]
        task_id="t",  # type: ignore[arg-type]
        action_type="public_page_read",
        normalized_target=TARGET_URL,
        parameter_digest="a" * 64,
        risk_level=RiskLevel.L0,
        idempotency_key="k",
    )
    decision = PolicyDecision(
        kind=DecisionKind.ALLOW,
        reason="automatic_policy_allow",
        risk_level=action.risk_level,
        target=normalize_target(TARGET_URL),
        requires_dns_recheck=True,
    )

    result = RefusingExecutor().execute(action, decision=decision)

    assert not result.succeeded
    assert result.reason == "no_execution_backend"


def test_a_full_cycle_captures_evidence_and_records_an_observation(engine: Engine) -> None:
    factory = session_factory(engine)
    transport = StubTransport()
    with factory() as session:
        engagement_id = seed_engagement(session)
        mission = seed_mission(session, engagement_id)
        lead = seed_lead(session, engagement_id, MissionId(mission.id))
        session.commit()

        controller = MissionController(
            session,
            MissionId(mission.id),
            planner=DeterministicPlanner(),
            executor=HttpCaptureExecutor(
                session, transport, engagement_id=engagement_id, clock=lambda: NOW
            ),
            clock=lambda: NOW,
        )
        report = controller.run_cycle(controller.start_run())

        evidence = list(session.scalars(select(EvidenceRecord)))
        observations = ObservationRepository(session).list_for_subject(
            engagement_id, TARGET_HOST
        )
        actions = ActionRepository(session).list_for_engagement(engagement_id)
        stored_lead = LeadRepository(session).get(LeadId(lead.id))

    assert report.outcomes[0].disposition == "executed"
    assert len(transport.requests) == 1
    assert transport.requests[0].target == TARGET_URL
    assert len(evidence) == 1
    assert len(observations) == 1
    assert observations[0].summary == "status=200 bytes=19"
    assert [item.entity.state for item in actions] == [ActionState.SUCCEEDED]
    assert stored_lead is not None
    assert stored_lead.entity.status is LeadStatus.WAITING


def test_a_transport_failure_is_reported_without_evidence(engine: Engine) -> None:
    factory = session_factory(engine)
    transport = StubTransport(error=CaptureTransportError("transport_scope_denied"))
    with factory() as session:
        engagement_id = seed_engagement(session)
        mission = seed_mission(session, engagement_id)
        lead = seed_lead(session, engagement_id, MissionId(mission.id))
        session.commit()

        controller = MissionController(
            session,
            MissionId(mission.id),
            planner=DeterministicPlanner(),
            executor=HttpCaptureExecutor(
                session, transport, engagement_id=engagement_id, clock=lambda: NOW
            ),
            clock=lambda: NOW,
        )
        report = controller.run_cycle(controller.start_run())

        evidence = list(session.scalars(select(EvidenceRecord)))
        stored_lead = LeadRepository(session).get(LeadId(lead.id))

    assert report.outcomes[0].disposition == "failed"
    assert evidence == []
    assert stored_lead is not None
    assert stored_lead.entity.failure_count == 1
    assert stored_lead.entity.next_attempt_at is not None


def test_an_unsupported_action_type_is_refused_by_the_executor(engine: Engine) -> None:
    factory = session_factory(engine)
    transport = StubTransport()
    with factory() as session:
        engagement_id = seed_engagement(session)
        executor = HttpCaptureExecutor(session, transport, engagement_id=engagement_id)
        action = Action(
            engagement_id=engagement_id,
            task_id="task",  # type: ignore[arg-type]
            action_type="port_scan",
            normalized_target=TARGET_URL,
            parameter_digest="a" * 64,
            risk_level=RiskLevel.L1,
            idempotency_key="k",
        )
        decision = PolicyDecision(
            kind=DecisionKind.ALLOW,
            reason="automatic_policy_allow",
            risk_level=action.risk_level,
            target=normalize_target(TARGET_URL),
            requires_dns_recheck=True,
        )

        result = executor.execute(action, decision=decision)

    assert not result.succeeded
    assert result.reason == "action_type_not_supported"
    assert transport.requests == []
