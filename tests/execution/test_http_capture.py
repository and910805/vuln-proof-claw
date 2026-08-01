"""Tests for the fail-closed structured HTTP capture coordinator."""

from __future__ import annotations

import json
from collections.abc import Generator
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Literal, cast

import pytest
from sqlalchemy import Engine

from vuln_proof_claw.domain.enums import ActionState, RiskLevel
from vuln_proof_claw.domain.errors import DomainValidationError
from vuln_proof_claw.domain.identifiers import new_action_id
from vuln_proof_claw.domain.models import Action, Approval, Engagement, Flow, Project, Task
from vuln_proof_claw.evidence.persistence import PersistentEvidenceStore
from vuln_proof_claw.execution.http_capture import (
    CapturePolicyError,
    HttpCaptureCoordinator,
    HttpCaptureLimits,
    HttpCaptureRequest,
    HttpCaptureResponse,
    capture_parameter_digest,
)
from vuln_proof_claw.persistence.base import Base
from vuln_proof_claw.persistence.repositories import (
    ActionRepository,
    ApprovalRepository,
    EngagementRepository,
    FlowRepository,
    ProjectRepository,
    ScopeRepository,
    TaskRepository,
)
from vuln_proof_claw.persistence.session import create_engine, create_session_factory
from vuln_proof_claw.policy.scope import EngagementScope

NOW = datetime(2026, 8, 1, 12, 0, tzinfo=UTC)


class FakeTransport:
    identity = "fake-http-transport@sha256:test"

    def __init__(self, response: HttpCaptureResponse | None = None) -> None:
        self.response = response or HttpCaptureResponse(
            status_code=200,
            final_target="https://example.test:443/public",
            headers=(("content-type", "text/plain"),),
            body=b"hello",
            duration_ms=12,
        )
        self.calls = 0

    def send(
        self,
        request: HttpCaptureRequest,
        limits: HttpCaptureLimits,
    ) -> HttpCaptureResponse:
        del request, limits
        self.calls += 1
        return self.response


@pytest.fixture
def engine(tmp_path: Path) -> Generator[Engine, None, None]:
    result = create_engine(f"sqlite:///{tmp_path / 'capture.db'}", pool_pre_ping=False)
    Base.metadata.create_all(result)
    yield result
    result.dispose()


def seed_capture_action(engine: Engine) -> tuple[Engagement, Action, HttpCaptureRequest]:
    action_id = new_action_id()
    request = HttpCaptureRequest(
        action_id=action_id,
        method="GET",
        target="https://example.test/public",
        headers=(("Accept", "text/plain"),),
    )
    project = Project(name="Acme", created_at=NOW)
    engagement = Engagement(
        project_id=project.id,
        name="Public page capture",
        starts_at=NOW - timedelta(hours=1),
        ends_at=NOW + timedelta(days=1),
        maximum_risk=RiskLevel.L0,
        created_at=NOW - timedelta(hours=1),
    )
    flow = Flow(engagement_id=engagement.id, objective="Capture", created_at=NOW)
    task = Task(flow_id=flow.id, title="GET public page", created_at=NOW)
    action = Action(
        id=action_id,
        engagement_id=engagement.id,
        task_id=task.id,
        action_type="public_page_read",
        normalized_target=request.target,
        parameter_digest=capture_parameter_digest(request),
        risk_level=RiskLevel.L0,
        idempotency_key="capture-public-page",
        state=ActionState.QUEUED,
        created_at=NOW,
    )
    scope = EngagementScope.create(
        allowed_hostnames=("example.test",),
        allowed_ports=(443,),
        allowed_schemes=("https",),
        allowed_paths=("/public",),
        valid_from=engagement.starts_at,
        valid_until=engagement.ends_at,
    )
    session_factory = create_session_factory(engine)
    with session_factory.begin() as session:
        ProjectRepository(session).add(project)
        EngagementRepository(session).add(engagement)
        ScopeRepository(session).add(engagement.id, scope)
        FlowRepository(session).add(flow)
        TaskRepository(session).add(task)
        ActionRepository(session).add(action)
    return engagement, action, request


def seed_approved_capture_action(
    engine: Engine,
    *,
    expires_at: datetime,
) -> tuple[Action, Approval, HttpCaptureRequest]:
    action_id = new_action_id()
    request = HttpCaptureRequest(
        action_id=action_id,
        method="GET",
        target="https://example.test/public",
    )
    project = Project(name="Approval capture", created_at=NOW - timedelta(hours=1))
    engagement = Engagement(
        project_id=project.id,
        name="Approved active validation",
        starts_at=NOW - timedelta(hours=1),
        ends_at=NOW + timedelta(days=1),
        maximum_risk=RiskLevel.L2,
        created_at=NOW - timedelta(hours=1),
    )
    flow = Flow(engagement_id=engagement.id, objective="Validate", created_at=NOW)
    task = Task(flow_id=flow.id, title="Approved request", created_at=NOW)
    approval = Approval(
        engagement_id=engagement.id,
        action_type="exploit_attempt",
        normalized_target=request.target,
        parameter_digest=capture_parameter_digest(request),
        risk_level=RiskLevel.L2,
        expires_at=expires_at,
        permitted_executions=1,
        approver="security-lead@example.test",
        approved_at=NOW - timedelta(minutes=10),
    )
    action = Action(
        id=action_id,
        engagement_id=engagement.id,
        task_id=task.id,
        action_type=approval.action_type,
        normalized_target=request.target,
        parameter_digest=approval.parameter_digest,
        risk_level=approval.risk_level,
        idempotency_key="approved-capture",
        state=ActionState.QUEUED,
        approval_id=approval.id,
        created_at=NOW - timedelta(minutes=5),
    )
    scope = EngagementScope.create(
        allowed_hostnames=("example.test",),
        allowed_ports=(443,),
        allowed_schemes=("https",),
        allowed_paths=("/public",),
        valid_from=engagement.starts_at,
        valid_until=engagement.ends_at,
    )
    session_factory = create_session_factory(engine)
    with session_factory.begin() as session:
        ProjectRepository(session).add(project)
        EngagementRepository(session).add(engagement)
        ScopeRepository(session).add(engagement.id, scope)
        FlowRepository(session).add(flow)
        TaskRepository(session).add(task)
        ApprovalRepository(session).add(approval)
        ActionRepository(session).add(action)
    return action, approval, request


def test_capture_persists_bounded_structured_evidence(engine: Engine) -> None:
    engagement, action, request = seed_capture_action(engine)
    transport = FakeTransport()
    session_factory = create_session_factory(engine)
    with session_factory.begin() as session:
        result = HttpCaptureCoordinator(session, transport).capture(request, at=NOW)
        assert result.evidence is not None
        raw = PersistentEvidenceStore(session).read_raw(result.evidence.metadata.evidence_id)

    assert transport.calls == 1
    assert result.action_state is ActionState.SUCCEEDED
    assert raw is not None
    payload = json.loads(raw)
    assert payload["request"]["target"] == "https://example.test:443/public"
    assert payload["response"]["body_base64"] == "aGVsbG8="
    with session_factory() as session:
        stored = ActionRepository(session).get(action.id)
        verification = PersistentEvidenceStore(session).verify_engagement(engagement.id)
    assert stored is not None
    assert stored.entity.state is ActionState.SUCCEEDED
    assert verification.valid


def test_capture_rejects_changed_parameters_before_transport(engine: Engine) -> None:
    _engagement, _action, request = seed_capture_action(engine)
    changed = HttpCaptureRequest(
        action_id=request.action_id,
        method="GET",
        target=request.target,
        headers=(("accept", "application/json"),),
    )
    transport = FakeTransport()
    session_factory = create_session_factory(engine)
    with session_factory.begin() as session, pytest.raises(
        CapturePolicyError,
        match="parameter_digest_mismatch",
    ):
        HttpCaptureCoordinator(session, transport).capture(changed, at=NOW)
    assert transport.calls == 0


def test_capture_rejects_redirect_and_marks_action_failed(engine: Engine) -> None:
    _engagement, action, request = seed_capture_action(engine)
    transport = FakeTransport(
        HttpCaptureResponse(
            status_code=302,
            final_target="https://example.test:443/login",
            headers=(("location", "/login"),),
            body=b"",
            duration_ms=5,
        )
    )
    session_factory = create_session_factory(engine)
    with session_factory.begin() as session:
        result = HttpCaptureCoordinator(session, transport).capture(request, at=NOW)

    with session_factory() as session:
        stored = ActionRepository(session).get(action.id)
    assert result.evidence is None
    assert result.error_code == "redirect_or_target_change_rejected"
    assert result.action_state is ActionState.FAILED
    assert stored is not None
    assert stored.entity.state is ActionState.FAILED


def test_approved_capture_consumes_single_use_approval_at_execution_start(
    engine: Engine,
) -> None:
    action, approval, request = seed_approved_capture_action(
        engine,
        expires_at=NOW + timedelta(minutes=10),
    )
    transport = FakeTransport()
    session_factory = create_session_factory(engine)
    with session_factory.begin() as session:
        result = HttpCaptureCoordinator(session, transport).capture(request, at=NOW)

    with session_factory() as session:
        stored_action = ActionRepository(session).get(action.id)
        stored_approval = ApprovalRepository(session).get(approval.id)
    assert result.action_state is ActionState.SUCCEEDED
    assert transport.calls == 1
    assert stored_action is not None
    assert stored_action.entity.approval_id == approval.id
    assert stored_approval is not None
    assert stored_approval.entity.consumed_executions == 1


def test_expired_approval_is_rejected_before_transport_and_not_consumed(
    engine: Engine,
) -> None:
    _action, approval, request = seed_approved_capture_action(engine, expires_at=NOW)
    transport = FakeTransport()
    session_factory = create_session_factory(engine)
    with session_factory.begin() as session, pytest.raises(
        CapturePolicyError,
        match="approval_invalid",
    ):
        HttpCaptureCoordinator(session, transport).capture(request, at=NOW)

    with session_factory() as session:
        stored_approval = ApprovalRepository(session).get(approval.id)
    assert transport.calls == 0
    assert stored_approval is not None
    assert stored_approval.entity.consumed_executions == 0


def test_capture_contract_rejects_unsafe_method_and_headers() -> None:
    with pytest.raises(DomainValidationError, match="GET and HEAD"):
        HttpCaptureRequest(
            action_id=new_action_id(),
            method=cast("Literal['GET', 'HEAD']", "POST"),
            target="https://example.test/",
        )
    with pytest.raises(DomainValidationError, match="not allowed"):
        HttpCaptureRequest(
            action_id=new_action_id(),
            method="GET",
            target="https://example.test/",
            headers=(("Authorization", "Bearer secret"),),
        )
