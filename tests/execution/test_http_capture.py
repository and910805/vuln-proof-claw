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
    HttpCaptureResult,
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


def seed_capture_action(
    engine: Engine,
    *,
    method: Literal["GET", "HEAD"] = "GET",
    headers: tuple[tuple[str, str], ...] = (("Accept", "text/plain"),),
    stored_target: str | None = None,
) -> tuple[Engagement, Action, HttpCaptureRequest]:
    action_id = new_action_id()
    request = HttpCaptureRequest(
        action_id=action_id,
        method=method,
        target="https://example.test/public",
        headers=headers,
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
        normalized_target=stored_target or request.target,
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


class ExplodingTransport:
    """Stands in for a transport whose network layer fails part-way through a request."""

    identity = "exploding-http-transport@sha256:test"

    def __init__(self, error: BaseException) -> None:
        self.error = error
        self.calls = 0

    def send(
        self,
        request: HttpCaptureRequest,
        limits: HttpCaptureLimits,
    ) -> HttpCaptureResponse:
        del request, limits
        self.calls += 1
        raise self.error


def test_a_capture_for_an_unknown_action_is_refused_before_any_connection(
    engine: Engine,
) -> None:
    request = HttpCaptureRequest(
        action_id=new_action_id(),
        method="GET",
        target="https://example.test/public",
    )
    transport = FakeTransport()
    session_factory = create_session_factory(engine)
    with session_factory.begin() as session, pytest.raises(
        CapturePolicyError,
        match="action_not_found",
    ):
        HttpCaptureCoordinator(session, transport).capture(request, at=NOW)
    assert transport.calls == 0


def test_a_target_that_differs_from_the_stored_action_is_refused_before_any_connection(
    engine: Engine,
) -> None:
    # The digest still matches the request, so only the target comparison can refuse a
    # request aimed somewhere other than the path the Action was authorized for.
    _engagement, _action, request = seed_capture_action(
        engine,
        stored_target="https://example.test:443/authorized",
    )
    transport = FakeTransport()
    session_factory = create_session_factory(engine)
    with session_factory.begin() as session, pytest.raises(
        CapturePolicyError,
        match="target_mismatch",
    ):
        HttpCaptureCoordinator(session, transport).capture(request, at=NOW)
    assert transport.calls == 0


def test_a_response_body_over_the_negotiated_limit_is_refused_and_stores_no_evidence(
    engine: Engine,
) -> None:
    engagement, action, request = seed_capture_action(engine)
    transport = FakeTransport(
        HttpCaptureResponse(
            status_code=200,
            final_target="https://example.test:443/public",
            headers=(("content-type", "text/plain"),),
            body=b"0123456789",
            duration_ms=7,
        )
    )
    session_factory = create_session_factory(engine)
    with session_factory.begin() as session:
        result = HttpCaptureCoordinator(session, transport).capture(
            request,
            limits=HttpCaptureLimits(max_response_bytes=4),
            at=NOW,
        )

    with session_factory() as session:
        stored = ActionRepository(session).get(action.id)
        persisted = PersistentEvidenceStore(session).metadata_for_engagement(engagement.id)
    assert result.error_code == "response_body_too_large"
    assert result.evidence is None
    assert result.response is None
    assert result.action_state is ActionState.FAILED
    assert persisted == ()
    assert stored is not None
    assert stored.entity.state is ActionState.FAILED


def test_a_head_capture_that_returns_a_body_is_refused(engine: Engine) -> None:
    _engagement, action, request = seed_capture_action(engine, method="HEAD")
    transport = FakeTransport(
        HttpCaptureResponse(
            status_code=200,
            final_target="https://example.test:443/public",
            headers=(("content-length", "6"),),
            body=b"leaked",
            duration_ms=4,
        )
    )
    session_factory = create_session_factory(engine)
    with session_factory.begin() as session:
        result = HttpCaptureCoordinator(session, transport).capture(request, at=NOW)

    with session_factory() as session:
        stored = ActionRepository(session).get(action.id)
    assert result.error_code == "head_response_body_rejected"
    assert result.response is None
    assert result.action_state is ActionState.FAILED
    assert stored is not None
    assert stored.entity.state is ActionState.FAILED


def test_a_head_capture_with_an_empty_body_is_still_accepted(engine: Engine) -> None:
    # The body check must be specific to HEAD responses that carry content; a check that
    # refused every HEAD would make the method unusable.
    _engagement, _action, request = seed_capture_action(engine, method="HEAD")
    transport = FakeTransport(
        HttpCaptureResponse(
            status_code=200,
            final_target="https://example.test:443/public",
            headers=(("content-length", "5"),),
            body=b"",
            duration_ms=3,
        )
    )
    session_factory = create_session_factory(engine)
    with session_factory.begin() as session:
        result = HttpCaptureCoordinator(session, transport).capture(request, at=NOW)
    assert result.action_state is ActionState.SUCCEEDED
    assert result.evidence is not None


def test_an_arbitrary_transport_failure_fails_the_action_closed_without_leaking_detail(
    engine: Engine,
) -> None:
    _engagement, action, request = seed_capture_action(engine)
    transport = ExplodingTransport(
        ConnectionResetError("dial tcp 203.0.113.7:443: connection reset by peer")
    )
    session_factory = create_session_factory(engine)
    with session_factory.begin() as session:
        result = HttpCaptureCoordinator(session, transport).capture(request, at=NOW)

    with session_factory() as session:
        stored = ActionRepository(session).get(action.id)
    assert result.error_code == "transport_failure"
    assert result.evidence is None
    assert result.response is None
    assert result.action_state is ActionState.FAILED
    assert stored is not None
    assert stored.entity.state is ActionState.FAILED


def test_capture_limits_refuse_an_unbounded_timeout_or_response_size() -> None:
    with pytest.raises(DomainValidationError, match="between 1 and 60 seconds"):
        HttpCaptureLimits(timeout_seconds=0)
    with pytest.raises(DomainValidationError, match="between 1 and 60 seconds"):
        HttpCaptureLimits(timeout_seconds=61)
    with pytest.raises(DomainValidationError, match="1 byte and 10 MiB"):
        HttpCaptureLimits(max_response_bytes=0)
    with pytest.raises(DomainValidationError, match="1 byte and 10 MiB"):
        HttpCaptureLimits(max_response_bytes=10 * 1024 * 1024 + 1)


def test_a_transport_reported_status_outside_the_http_range_is_refused() -> None:
    # A transport that reports 0 for "never connected" must not be recorded as evidence
    # of an HTTP status the target never sent.
    for status_code in (0, 99, 600):
        with pytest.raises(DomainValidationError, match="status code is invalid"):
            HttpCaptureResponse(
                status_code=status_code,
                final_target="https://example.test/public",
                headers=(),
                body=b"",
                duration_ms=1,
            )


def test_a_negative_capture_duration_is_refused() -> None:
    with pytest.raises(DomainValidationError, match="duration must not be negative"):
        HttpCaptureResponse(
            status_code=200,
            final_target="https://example.test/public",
            headers=(),
            body=b"",
            duration_ms=-1,
        )


def test_more_headers_than_the_limit_are_refused() -> None:
    too_many = tuple((f"x-index-{index}", str(index)) for index in range(101))
    with pytest.raises(DomainValidationError, match="header count exceeds limit"):
        HttpCaptureResponse(
            status_code=200,
            final_target="https://example.test/public",
            headers=too_many,
            body=b"",
            duration_ms=1,
        )


def test_headers_totalling_more_than_the_byte_limit_are_refused() -> None:
    with pytest.raises(DomainValidationError, match="exceed byte limit"):
        HttpCaptureRequest(
            action_id=new_action_id(),
            method="GET",
            target="https://example.test/public",
            headers=(("accept", "text/plain," * 8000),),
        )


def test_an_empty_header_name_or_value_is_refused() -> None:
    with pytest.raises(DomainValidationError, match="must not be empty"):
        HttpCaptureRequest(
            action_id=new_action_id(),
            method="GET",
            target="https://example.test/public",
            headers=(("", "text/plain"),),
        )
    with pytest.raises(DomainValidationError, match="must not be empty"):
        HttpCaptureRequest(
            action_id=new_action_id(),
            method="GET",
            target="https://example.test/public",
            headers=(("accept", "   "),),
        )


def test_a_header_carrying_a_line_break_or_nul_is_refused() -> None:
    # Header injection: a smuggled CRLF would let a caller append a header the Approval
    # never covered, and a NUL can truncate the request at a lower layer.
    for value in ("text/plain\r\nX-Smuggled: 1", "text/plain\nX-Smuggled: 1", "text/plain\x00"):
        with pytest.raises(DomainValidationError, match="control delimiters"):
            HttpCaptureRequest(
                action_id=new_action_id(),
                method="GET",
                target="https://example.test/public",
                headers=(("accept", value),),
            )
    with pytest.raises(DomainValidationError, match="control delimiters"):
        HttpCaptureResponse(
            status_code=200,
            final_target="https://example.test/public",
            headers=(("x-note", "a\r\nset-cookie: forged"),),
            body=b"",
            duration_ms=1,
        )


def test_a_duplicate_request_header_is_refused() -> None:
    # Duplicates would make the digest depend on which copy a transport happened to send,
    # breaking the binding between the Approval and the request actually issued.
    with pytest.raises(DomainValidationError, match="duplicate HTTP header"):
        HttpCaptureRequest(
            action_id=new_action_id(),
            method="GET",
            target="https://example.test/public",
            headers=(("Accept", "text/plain"), ("accept", "text/html")),
        )


def test_a_successful_result_must_carry_evidence_and_a_response_and_no_error_code(
    engine: Engine,
) -> None:
    # A caller must never be handed a SUCCEEDED result it cannot audit: no evidence, a
    # lingering error code, or a missing response all mean the capture did not happen.
    _engagement, _action, request = seed_capture_action(engine)
    transport = FakeTransport()
    session_factory = create_session_factory(engine)
    with session_factory.begin() as session:
        succeeded = HttpCaptureCoordinator(session, transport).capture(request, at=NOW)
    evidence = succeeded.evidence
    response = succeeded.response
    assert evidence is not None
    assert response is not None

    with pytest.raises(DomainValidationError, match="requires evidence"):
        HttpCaptureResult(
            evidence=None,
            action_state=ActionState.SUCCEEDED,
            response=response,
        )
    with pytest.raises(DomainValidationError, match="must not have an error code"):
        HttpCaptureResult(
            evidence=evidence,
            action_state=ActionState.SUCCEEDED,
            error_code="transport_failure",
            response=response,
        )
    with pytest.raises(DomainValidationError, match="requires a response"):
        HttpCaptureResult(
            evidence=evidence,
            action_state=ActionState.SUCCEEDED,
        )


def test_a_failed_result_requires_an_error_code_and_must_not_expose_a_response() -> None:
    response = HttpCaptureResponse(
        status_code=200,
        final_target="https://example.test/public",
        headers=(),
        body=b"hello",
        duration_ms=1,
    )
    with pytest.raises(DomainValidationError, match="requires an error code"):
        HttpCaptureResult(evidence=None, action_state=ActionState.FAILED)
    with pytest.raises(DomainValidationError, match="must not expose a response"):
        HttpCaptureResult(
            evidence=None,
            action_state=ActionState.FAILED,
            error_code="transport_failure",
            response=response,
        )


def test_the_parameter_digest_does_not_depend_on_header_order() -> None:
    # The digest is what binds an approved Action to the request that may be replayed
    # for it. `_normalize_headers` ends in `sorted(...)`, and that sort is the only
    # reason the same authorised request survives being presented with its headers in a
    # different order. Delete the sort and a legitimate replay is refused with
    # parameter_digest_mismatch, so this fails closed - it costs availability, not
    # safety, which is exactly why no other test would notice.
    action_id = new_action_id()
    first = HttpCaptureRequest(
        action_id=action_id,
        method="GET",
        target="https://example.test/index.html",
        headers=(("accept", "text/html"), ("user-agent", "proofclaw")),
    )
    second = HttpCaptureRequest(
        action_id=action_id,
        method="GET",
        target="https://example.test/index.html",
        headers=(("user-agent", "proofclaw"), ("accept", "text/html")),
    )
    assert capture_parameter_digest(first) == capture_parameter_digest(second)


def test_the_parameter_digest_ignores_header_case_and_surrounding_space() -> None:
    # Same guarantee, the other half of the normalisation: a caller that sends
    # "Accept" with a padded value must hash to the digest the Action was approved with.
    action_id = new_action_id()
    canonical = HttpCaptureRequest(
        action_id=action_id,
        method="GET",
        target="https://example.test/index.html",
        headers=(("accept", "text/html"),),
    )
    as_sent = HttpCaptureRequest(
        action_id=action_id,
        method="GET",
        target="https://example.test/index.html",
        headers=(("Accept", "  text/html  "),),
    )
    assert capture_parameter_digest(canonical) == capture_parameter_digest(as_sent)


def test_a_different_header_value_changes_the_parameter_digest() -> None:
    # The counterpart: normalisation must not flatten a real difference away, or the
    # digest would stop binding the Action to anything.
    action_id = new_action_id()
    approved = HttpCaptureRequest(
        action_id=action_id,
        method="GET",
        target="https://example.test/index.html",
        headers=(("accept", "text/html"),),
    )
    drifted = HttpCaptureRequest(
        action_id=action_id,
        method="GET",
        target="https://example.test/index.html",
        headers=(("accept", "application/json"),),
    )
    assert capture_parameter_digest(approved) != capture_parameter_digest(drifted)
