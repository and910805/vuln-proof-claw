"""Durable Action-to-Worker lifecycle integration tests."""

from __future__ import annotations

import base64
import hashlib
import json
from collections.abc import Generator
from dataclasses import replace
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
from sqlalchemy import Engine

from vuln_proof_claw.domain.enums import ActionState, RiskLevel, WorkerState
from vuln_proof_claw.domain.errors import DomainValidationError
from vuln_proof_claw.domain.identifiers import (
    ActionId,
    EngagementId,
    EvidenceId,
    WorkerId,
    new_action_id,
    new_approval_id,
    new_engagement_id,
    new_worker_id,
)
from vuln_proof_claw.domain.models import (
    Action,
    Engagement,
    Evidence,
    Flow,
    Project,
    Task,
    WorkerExecution,
)
from vuln_proof_claw.evidence.persistence import PersistentEvidenceStore
from vuln_proof_claw.execution.http_capture import HttpCaptureRequest, capture_parameter_digest
from vuln_proof_claw.execution.lifecycle import ActionWorkerCoordinator, WorkerLifecycleError
from vuln_proof_claw.execution.manager import (
    DisabledWorkerManager,
    LifecycleWorkerManager,
    RuntimeResource,
    WorkerHandle,
    WorkerManagerError,
)
from vuln_proof_claw.execution.protocol import (
    WorkerHttpAction,
    WorkerHttpCapture,
    WorkerLimits,
    WorkerRequest,
    WorkerResponse,
    WorkerResultStatus,
    WorkerScope,
)
from vuln_proof_claw.persistence.base import Base
from vuln_proof_claw.persistence.models import EngagementScopeRecord
from vuln_proof_claw.persistence.repositories import (
    ActionRepository,
    AuditEventRepository,
    EngagementRepository,
    EvidenceRepository,
    FlowRepository,
    ProjectRepository,
    ScopeRepository,
    TaskRepository,
    WorkerExecutionRepository,
)
from vuln_proof_claw.persistence.session import create_engine, create_session_factory
from vuln_proof_claw.policy.scope import EngagementScope

NOW = datetime(2026, 8, 1, 12, 0, tzinfo=UTC)


class FakeRuntime:
    identity = "fake-runtime@sha256:lifecycle"

    def __init__(self) -> None:
        self.response: WorkerResponse | None = None
        self.calls: list[str] = []
        self.start_error: Exception | None = None

    async def create(self, request: WorkerRequest, *, worker_id: WorkerId) -> str:
        del request
        self.worker_id = worker_id
        self.calls.append("create")
        return "runtime-1"

    async def list_resources(self) -> tuple[RuntimeResource, ...]:
        return ()

    async def start(self, reference: str) -> None:
        assert reference == "runtime-1"
        self.calls.append("start")
        if self.start_error is not None:
            raise self.start_error

    async def wait(self, reference: str) -> WorkerResponse:
        assert reference == "runtime-1"
        self.calls.append("wait")
        assert self.response is not None
        return self.response

    async def cancel(self, reference: str) -> None:
        assert reference == "runtime-1"
        self.calls.append("cancel")

    async def destroy(self, reference: str) -> None:
        assert reference == "runtime-1"
        self.calls.append("destroy")


@pytest.fixture
def engine(tmp_path: Path) -> Generator[Engine, None, None]:
    result = create_engine(f"sqlite:///{tmp_path / 'lifecycle.db'}", pool_pre_ping=False)
    Base.metadata.create_all(result)
    yield result
    result.dispose()


def seed_action(engine: Engine) -> tuple[Engagement, Action, WorkerRequest]:
    project = Project(name="Lifecycle", created_at=NOW)
    engagement = Engagement(
        project_id=project.id,
        name="Disposable workers",
        starts_at=NOW - timedelta(hours=1),
        ends_at=NOW + timedelta(days=1),
        maximum_risk=RiskLevel.L0,
        created_at=NOW,
    )
    flow = Flow(engagement_id=engagement.id, objective="Validate", created_at=NOW)
    task = Task(flow_id=flow.id, title="Capture", created_at=NOW)
    action_id = new_action_id()
    capture_request = HttpCaptureRequest(
        action_id=action_id,
        method="GET",
        target="https://example.test:443/public",
    )
    action = Action(
        id=action_id,
        engagement_id=engagement.id,
        task_id=task.id,
        action_type="public_page_read",
        normalized_target="https://example.test:443/public",
        parameter_digest=capture_parameter_digest(capture_request),
        risk_level=RiskLevel.L0,
        idempotency_key="lifecycle-1",
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
    worker_request = WorkerRequest(
        request_id="worker-request-1",
        engagement_id=engagement.id,
        action_id=action.id,
        action_type=action.action_type,
        normalized_target=action.normalized_target,
        parameter_digest=action.parameter_digest,
        risk_level=action.risk_level,
        idempotency_key=action.idempotency_key,
        capabilities=("http_client",),
        http_action=WorkerHttpAction(method="GET"),
        scope=WorkerScope(
            allowed_hostnames=("example.test",),
            allowed_ports=(443,),
            allowed_schemes=("https",),
            allowed_paths=("/public",),
        ),
        limits=WorkerLimits(
            timeout_seconds=30,
            memory_megabytes=256,
            cpu_count=1,
            process_limit=64,
        ),
    )
    session_factory = create_session_factory(engine)
    with session_factory.begin() as session:
        ProjectRepository(session).add(project)
        EngagementRepository(session).add(engagement)
        ScopeRepository(session).add(engagement.id, scope)
        FlowRepository(session).add(flow)
        TaskRepository(session).add(task)
        ActionRepository(session).add(action)
    return engagement, action, worker_request


async def test_success_requires_persisted_evidence_and_records_lifecycle(engine: Engine) -> None:
    engagement, action, worker_request = seed_action(engine)
    evidence = Evidence(
        action_id=action.id,
        tool_name="fake-worker",
        tool_version="1",
        digest="b" * 64,
        captured_at=NOW,
    )
    runtime = FakeRuntime()
    runtime.response = _response(worker_request, WorkerResultStatus.SUCCEEDED, evidence.id)
    session_factory = create_session_factory(engine)
    with session_factory.begin() as session:
        EvidenceRepository(session).add(evidence)
        manager = LifecycleWorkerManager(runtime, clock=lambda: NOW)
        coordinator = ActionWorkerCoordinator(session, manager)
        handle = await coordinator.start(worker_request, actor="operator:test", at=NOW)
        restarted_coordinator = ActionWorkerCoordinator(session, manager)
        await restarted_coordinator.collect(
            handle.worker_id,
            at=NOW + timedelta(seconds=1),
        )

    with session_factory() as session:
        stored = ActionRepository(session).get(action.id)
        stored_execution = WorkerExecutionRepository(session).get(handle.worker_id)
        events = AuditEventRepository(session).list_for_engagement(engagement.id)
    assert stored is not None
    assert stored.entity.state is ActionState.SUCCEEDED
    assert stored_execution is not None
    assert stored_execution.entity.state is WorkerState.COMPLETED
    assert stored_execution.entity.cleaned_up
    assert {event.event_type for event in events} >= {
        "worker.created",
        "worker.started",
        "worker.collected",
        "worker.destroyed",
    }
    assert runtime.calls == ["create", "start", "wait", "destroy"]


async def test_inline_worker_capture_is_revalidated_persisted_and_replaced(
    engine: Engine,
) -> None:
    engagement, action, worker_request = seed_action(engine)
    runtime = FakeRuntime()
    runtime.response = _capture_response(worker_request)
    session_factory = create_session_factory(engine)

    with session_factory.begin() as session:
        coordinator = ActionWorkerCoordinator(session, LifecycleWorkerManager(runtime))
        handle = await coordinator.start(worker_request, actor="operator:test", at=NOW)
        response = await coordinator.collect(handle.worker_id, at=NOW + timedelta(seconds=1))
        assert len(response.evidence_ids) == 1
        assert response.http_captures == ()
        raw = PersistentEvidenceStore(session).read_raw(response.evidence_ids[0])

    assert raw is not None
    payload = json.loads(raw)
    assert payload["request"] == {
        "headers": [],
        "method": "GET",
        "target": "https://example.test:443/public",
    }
    assert payload["response"]["body_base64"] == "aGVsbG8="
    with session_factory() as session:
        stored = ActionRepository(session).get(action.id)
        verification = PersistentEvidenceStore(session).verify_engagement(engagement.id)
    assert stored is not None
    assert stored.entity.state is ActionState.SUCCEEDED
    assert verification.valid


@pytest.mark.parametrize(
    "capture",
    [
        WorkerHttpCapture(
            method="GET",
            request_target="https://example.test:443/public",
            request_headers=(("accept", "application/json"),),
            status_code=200,
            final_target="https://example.test:443/public",
            body_base64="",
            body_sha256=hashlib.sha256(b"").hexdigest(),
            captured_at=NOW,
            duration_ms=1,
        ),
        WorkerHttpCapture(
            method="GET",
            request_target="https://example.test:443/public",
            status_code=200,
            final_target="https://example.test:443/public",
            body_base64="",
            body_sha256=hashlib.sha256(b"").hexdigest(),
            captured_at=NOW + timedelta(days=2),
            duration_ms=1,
        ),
    ],
    ids=("parameter-drift", "expired-scope"),
)
async def test_untrusted_inline_capture_fails_without_persisting_evidence(
    engine: Engine,
    capture: WorkerHttpCapture,
) -> None:
    _engagement, action, worker_request = seed_action(engine)
    runtime = FakeRuntime()
    runtime.response = _capture_response(worker_request, capture=capture)
    session_factory = create_session_factory(engine)

    with session_factory.begin() as session:
        coordinator = ActionWorkerCoordinator(session, LifecycleWorkerManager(runtime))
        handle = await coordinator.start(worker_request, actor="operator:test", at=NOW)
        response = await coordinator.collect(handle.worker_id, at=capture.captured_at)

    assert response.status is WorkerResultStatus.FAILED
    assert response.error_code == "worker_capture_binding_invalid"
    assert response.evidence_ids == ()
    with session_factory() as session:
        stored = ActionRepository(session).get(action.id)
        evidence = EvidenceRepository(session).for_action(action.id)
    assert stored is not None
    assert stored.entity.state is ActionState.FAILED
    assert evidence == ()


async def test_unpersisted_or_cross_action_evidence_fails_action(engine: Engine) -> None:
    _engagement, action, worker_request = seed_action(engine)
    missing = Evidence(action_id=action.id, tool_name="fake", tool_version="1", digest="b" * 64)
    runtime = FakeRuntime()
    runtime.response = _response(worker_request, WorkerResultStatus.SUCCEEDED, missing.id)
    session_factory = create_session_factory(engine)
    with session_factory.begin() as session:
        coordinator = ActionWorkerCoordinator(session, LifecycleWorkerManager(runtime))
        handle = await coordinator.start(worker_request, actor="operator:test", at=NOW)
        response = await coordinator.collect(handle.worker_id, at=NOW)
    with session_factory() as session:
        stored = ActionRepository(session).get(action.id)
    assert stored is not None
    assert stored.entity.state is ActionState.FAILED
    assert response.status is WorkerResultStatus.FAILED
    assert response.error_code == "worker_evidence_binding_invalid"


async def test_cancel_closes_action_and_destroys_worker(engine: Engine) -> None:
    _engagement, action, worker_request = seed_action(engine)
    runtime = FakeRuntime()
    session_factory = create_session_factory(engine)
    with session_factory.begin() as session:
        coordinator = ActionWorkerCoordinator(session, LifecycleWorkerManager(runtime))
        handle = await coordinator.start(worker_request, actor="operator:test", at=NOW)
        await coordinator.cancel(handle.worker_id, actor="operator:test", at=NOW)
    with session_factory() as session:
        stored = ActionRepository(session).get(action.id)
    assert stored is not None
    assert stored.entity.state is ActionState.CANCELLED
    assert runtime.calls == ["create", "start", "cancel", "destroy"]


async def test_timeout_response_closes_action_as_timed_out(engine: Engine) -> None:
    _engagement, action, worker_request = seed_action(engine)
    runtime = FakeRuntime()
    runtime.response = WorkerResponse(
        request_id=worker_request.request_id,
        engagement_id=worker_request.engagement_id,
        action_id=worker_request.action_id,
        status=WorkerResultStatus.TIMED_OUT,
        started_at=NOW,
        completed_at=NOW + timedelta(seconds=30),
        error_code="worker_timed_out",
    )
    session_factory = create_session_factory(engine)
    with session_factory.begin() as session:
        coordinator = ActionWorkerCoordinator(session, LifecycleWorkerManager(runtime))
        handle = await coordinator.start(worker_request, actor="operator:test", at=NOW)
        await coordinator.collect(handle.worker_id, at=NOW + timedelta(seconds=30))
    with session_factory() as session:
        stored = ActionRepository(session).get(action.id)
    assert stored is not None
    assert stored.entity.state is ActionState.TIMED_OUT


async def test_start_failure_marks_worker_lost_after_cleanup(engine: Engine) -> None:
    _engagement, action, worker_request = seed_action(engine)
    runtime = FakeRuntime()
    runtime.start_error = RuntimeError("private runtime detail")
    session_factory = create_session_factory(engine)
    with session_factory.begin() as session:
        coordinator = ActionWorkerCoordinator(session, LifecycleWorkerManager(runtime))
        handle = await coordinator.start(worker_request, actor="operator:test", at=NOW)
    with session_factory() as session:
        stored = ActionRepository(session).get(action.id)
    assert stored is not None
    assert stored.entity.state is ActionState.WORKER_LOST
    assert handle.error_code == "worker_start_failed"
    assert runtime.calls == ["create", "start", "destroy"]


async def test_changed_action_binding_is_refused_before_runtime_create(engine: Engine) -> None:
    _engagement, _action, worker_request = seed_action(engine)
    runtime = FakeRuntime()
    changed = worker_request.model_copy(update={"parameter_digest": "c" * 64})
    session_factory = create_session_factory(engine)
    with session_factory.begin() as session:
        coordinator = ActionWorkerCoordinator(session, LifecycleWorkerManager(runtime))
        with pytest.raises(WorkerLifecycleError, match="action_binding_mismatch"):
            await coordinator.start(changed, actor="operator:test", at=NOW)
    assert runtime.calls == []


async def test_restart_reconciliation_closes_running_action_as_worker_lost(
    engine: Engine,
) -> None:
    engagement, action, worker_request = seed_action(engine)
    runtime = FakeRuntime()
    session_factory = create_session_factory(engine)
    with session_factory.begin() as session:
        coordinator = ActionWorkerCoordinator(session, LifecycleWorkerManager(runtime))
        handle = await coordinator.start(worker_request, actor="operator:test", at=NOW)

    with session_factory.begin() as session:
        recovery = ActionWorkerCoordinator(
            session,
            DisabledWorkerManager(),
        )
        reconciled = recovery.reconcile_after_restart(at=NOW + timedelta(minutes=1))
        assert recovery.reconcile_after_restart(at=NOW + timedelta(minutes=2)) == ()

    with session_factory() as session:
        stored_action = ActionRepository(session).get(action.id)
        stored_execution = WorkerExecutionRepository(session).get(handle.worker_id)
        events = AuditEventRepository(session).list_for_engagement(engagement.id)
    assert len(reconciled) == 1
    assert stored_action is not None
    assert stored_action.entity.state is ActionState.WORKER_LOST
    assert stored_execution is not None
    assert stored_execution.entity.state is WorkerState.LOST
    assert not stored_execution.entity.cleaned_up
    assert stored_execution.entity.error_code == "worker_recovery_unavailable"
    assert "worker.reconciled_lost" in {event.event_type for event in events}
    assert runtime.calls == ["create", "start"]


def test_restart_reconciliation_tolerates_clock_rollback(engine: Engine) -> None:
    _engagement, _action, worker_request = seed_action(engine)
    future = NOW + timedelta(minutes=5)
    execution = WorkerExecution(
        request_id=worker_request.request_id,
        engagement_id=worker_request.engagement_id,
        action_id=worker_request.action_id,
        runtime_identity="previous-runtime@sha256:test",
        state=WorkerState.RUNNING,
        created_at=future,
        updated_at=future,
    )
    session_factory = create_session_factory(engine)
    with session_factory.begin() as session:
        WorkerExecutionRepository(session).add(execution)

    with session_factory.begin() as session:
        reconciled = ActionWorkerCoordinator(
            session,
            DisabledWorkerManager(),
        ).reconcile_after_restart(at=NOW)

    assert len(reconciled) == 1
    assert reconciled[0].state is WorkerState.LOST
    assert reconciled[0].updated_at == future


def test_restart_reconciliation_closes_action_after_worker_was_created(engine: Engine) -> None:
    _engagement, action, worker_request = seed_action(engine)
    execution = WorkerExecution(
        request_id=worker_request.request_id,
        engagement_id=worker_request.engagement_id,
        action_id=worker_request.action_id,
        runtime_identity="previous-runtime@sha256:test",
        state=WorkerState.STARTING,
        created_at=NOW,
        updated_at=NOW,
    )
    session_factory = create_session_factory(engine)
    with session_factory.begin() as session:
        WorkerExecutionRepository(session).add(execution)

    with session_factory.begin() as session:
        reconciled = ActionWorkerCoordinator(
            session,
            DisabledWorkerManager(),
        ).reconcile_after_restart(at=NOW + timedelta(minutes=1))

    with session_factory() as session:
        stored_action = ActionRepository(session).get(action.id)
        stored_execution = WorkerExecutionRepository(session).get(execution.id)
    assert len(reconciled) == 1
    assert stored_action is not None
    assert stored_action.entity.state is ActionState.WORKER_LOST
    assert stored_execution is not None
    assert stored_execution.entity.state is WorkerState.LOST


def _response(
    worker_request: WorkerRequest,
    status: WorkerResultStatus,
    evidence_id: EvidenceId,
) -> WorkerResponse:
    return WorkerResponse(
        request_id=worker_request.request_id,
        engagement_id=worker_request.engagement_id,
        action_id=worker_request.action_id,
        status=status,
        started_at=NOW,
        completed_at=NOW + timedelta(seconds=1),
        evidence_ids=(evidence_id,),
        exit_code=0,
    )


def _capture_response(
    worker_request: WorkerRequest,
    *,
    capture: WorkerHttpCapture | None = None,
) -> WorkerResponse:
    body = b"hello"
    inline = capture or WorkerHttpCapture(
        method="GET",
        request_target=worker_request.normalized_target,
        status_code=200,
        final_target=worker_request.normalized_target,
        response_headers=(("content-type", "text/plain"),),
        body_base64=base64.b64encode(body).decode(),
        body_sha256=hashlib.sha256(body).hexdigest(),
        captured_at=NOW,
        duration_ms=12,
    )
    return WorkerResponse(
        request_id=worker_request.request_id,
        engagement_id=worker_request.engagement_id,
        action_id=worker_request.action_id,
        status=WorkerResultStatus.SUCCEEDED,
        started_at=min(NOW, inline.captured_at),
        completed_at=max(NOW + timedelta(seconds=1), inline.captured_at),
        http_captures=(inline,),
        exit_code=0,
    )


class AnonymousRuntime(FakeRuntime):
    """A runtime that reports no immutable identity for its worker image."""

    identity = ""


class UndestroyableRuntime(FakeRuntime):
    """A runtime whose disposal fails, so the worker cannot be proven destroyed."""

    async def destroy(self, reference: str) -> None:
        assert reference == "runtime-1"
        self.calls.append("destroy")
        raise RuntimeError("private runtime detail")


class ScriptedWorkerManager:
    """A WorkerManager whose every reply is dictated by the test.

    The coordinator must never trust its manager, so this stands in for any other
    WorkerManager implementation - or a tampered worker channel - that reports a
    handle or a response the durable registry never authorized.
    """

    runtime_identity = "scripted-runtime@sha256:lifecycle"

    def __init__(self, request_id: str) -> None:
        self.handle = WorkerHandle(
            worker_id=new_worker_id(),
            request_id=request_id,
            state=WorkerState.STARTING,
            created_at=NOW,
            updated_at=NOW,
        )
        self.status_handle: WorkerHandle | None = None
        self.response: WorkerResponse | None = None
        self.start_error: WorkerManagerError | None = None
        self.calls: list[str] = []

    async def submit(self, request: WorkerRequest) -> WorkerHandle:
        del request
        self.calls.append("submit")
        return self.handle

    async def start(self, worker_id: str) -> WorkerHandle:
        del worker_id
        self.calls.append("start")
        if self.start_error is not None:
            raise self.start_error
        running = replace(self.handle, state=WorkerState.RUNNING)
        self.status_handle = running
        return running

    async def status(self, worker_id: str) -> WorkerHandle | None:
        del worker_id
        self.calls.append("status")
        return self.status_handle

    async def cancel(self, worker_id: str) -> WorkerHandle:
        del worker_id
        self.calls.append("cancel")
        return replace(self.handle, state=WorkerState.CANCELLED, cleaned_up=True)

    async def collect(self, worker_id: str) -> WorkerResponse | None:
        del worker_id
        self.calls.append("collect")
        return self.response


def _in_flight_execution(
    worker_request: WorkerRequest,
    *,
    request_id: str | None = None,
    action_id: ActionId | None = None,
    state: WorkerState = WorkerState.RUNNING,
) -> WorkerExecution:
    return WorkerExecution(
        request_id=request_id or worker_request.request_id,
        engagement_id=worker_request.engagement_id,
        action_id=action_id or worker_request.action_id,
        runtime_identity="previous-runtime@sha256:test",
        state=state,
        created_at=NOW,
        updated_at=NOW,
    )


def _payloads_for(
    engine: Engine,
    engagement_id: EngagementId,
    event_type: str,
) -> list[dict[str, object]]:
    session_factory = create_session_factory(engine)
    with session_factory() as session:
        events = AuditEventRepository(session).list_for_engagement(engagement_id)
    return [json.loads(event.payload) for event in events if event.event_type == event_type]


async def test_start_is_refused_when_the_action_is_not_persisted(engine: Engine) -> None:
    _engagement, _action, worker_request = seed_action(engine)
    orphan = worker_request.model_copy(update={"action_id": new_action_id()})
    runtime = FakeRuntime()
    session_factory = create_session_factory(engine)
    with session_factory.begin() as session:
        coordinator = ActionWorkerCoordinator(session, LifecycleWorkerManager(runtime))
        with pytest.raises(WorkerLifecycleError, match="action_not_found"):
            await coordinator.start(orphan, actor="operator:test", at=NOW)
    assert runtime.calls == []


async def test_start_is_refused_once_the_action_has_left_the_queue(engine: Engine) -> None:
    _engagement, action, worker_request = seed_action(engine)
    runtime = FakeRuntime()
    session_factory = create_session_factory(engine)
    with session_factory.begin() as session:
        coordinator = ActionWorkerCoordinator(
            session,
            LifecycleWorkerManager(runtime, clock=lambda: NOW),
        )
        await coordinator.start(worker_request, actor="operator:test", at=NOW)
        with pytest.raises(WorkerLifecycleError, match="action_not_queued"):
            await coordinator.start(worker_request, actor="operator:test", at=NOW)
    with session_factory() as session:
        stored = ActionRepository(session).get(action.id)
    assert stored is not None
    assert stored.entity.state is ActionState.RUNNING
    assert runtime.calls == ["create", "start"]


async def test_a_second_worker_cannot_be_registered_for_one_action(engine: Engine) -> None:
    _engagement, action, worker_request = seed_action(engine)
    runtime = FakeRuntime()
    session_factory = create_session_factory(engine)
    with session_factory.begin() as session:
        WorkerExecutionRepository(session).add(
            _in_flight_execution(worker_request, request_id="worker-request-earlier")
        )

    with session_factory.begin() as session:
        coordinator = ActionWorkerCoordinator(session, LifecycleWorkerManager(runtime))
        with pytest.raises(WorkerLifecycleError, match="worker_execution_already_registered"):
            await coordinator.start(worker_request, actor="operator:test", at=NOW)

    with session_factory() as session:
        stored = ActionRepository(session).get(action.id)
    assert stored is not None
    assert stored.entity.state is ActionState.QUEUED
    assert runtime.calls == []


async def test_a_replayed_request_id_cannot_start_a_second_worker(engine: Engine) -> None:
    _engagement, action, worker_request = seed_action(engine)
    sibling = replace(action, id=new_action_id(), idempotency_key="lifecycle-2")
    runtime = FakeRuntime()
    session_factory = create_session_factory(engine)
    with session_factory.begin() as session:
        ActionRepository(session).add(sibling)
        WorkerExecutionRepository(session).add(
            _in_flight_execution(worker_request, action_id=sibling.id)
        )

    with session_factory.begin() as session:
        coordinator = ActionWorkerCoordinator(session, LifecycleWorkerManager(runtime))
        with pytest.raises(WorkerLifecycleError, match="worker_request_already_registered"):
            await coordinator.start(worker_request, actor="operator:test", at=NOW)
    assert runtime.calls == []


async def test_a_worker_is_destroyed_when_its_registry_row_cannot_be_written(
    engine: Engine,
) -> None:
    _engagement, action, worker_request = seed_action(engine)
    runtime = AnonymousRuntime()
    session_factory = create_session_factory(engine)
    with session_factory.begin() as session:
        coordinator = ActionWorkerCoordinator(
            session,
            LifecycleWorkerManager(runtime, clock=lambda: NOW),
        )
        with pytest.raises(DomainValidationError, match="runtime_identity"):
            await coordinator.start(worker_request, actor="operator:test", at=NOW)

    with session_factory() as session:
        stored = ActionRepository(session).get(action.id)
        binding = WorkerExecutionRepository(session).get_for_action(action.id)
        events = AuditEventRepository(session).list_for_engagement(action.engagement_id)
    assert runtime.calls == ["create", "cancel", "destroy"]
    assert binding is None
    assert stored is not None
    assert stored.entity.state is ActionState.QUEUED
    assert events == ()


async def test_a_worker_is_destroyed_when_the_running_transition_is_refused(
    engine: Engine,
) -> None:
    _engagement, action, worker_request = seed_action(engine)
    before_creation = NOW - timedelta(minutes=30)
    runtime = FakeRuntime()
    session_factory = create_session_factory(engine)
    with session_factory.begin() as session:
        coordinator = ActionWorkerCoordinator(
            session,
            LifecycleWorkerManager(runtime, clock=lambda: before_creation),
        )
        with pytest.raises(DomainValidationError, match="started_at"):
            await coordinator.start(worker_request, actor="operator:test", at=before_creation)

    with session_factory() as session:
        stored = ActionRepository(session).get(action.id)
        binding = WorkerExecutionRepository(session).get_for_action(action.id)
        event_types = {
            event.event_type
            for event in AuditEventRepository(session).list_for_engagement(action.engagement_id)
        }
    assert runtime.calls == ["create", "cancel", "destroy"]
    assert stored is not None
    assert stored.entity.state is ActionState.QUEUED
    assert binding is not None
    assert binding.entity.state is WorkerState.CANCELLED
    assert binding.entity.cleaned_up
    assert event_types == {"worker.created", "worker.destroyed"}


async def test_start_refuses_when_a_failed_worker_cannot_be_accounted_for(
    engine: Engine,
) -> None:
    _engagement, action, worker_request = seed_action(engine)
    manager = ScriptedWorkerManager(worker_request.request_id)
    manager.start_error = WorkerManagerError("worker_start_failed")
    session_factory = create_session_factory(engine)
    with session_factory.begin() as session:
        coordinator = ActionWorkerCoordinator(session, manager)
        with pytest.raises(WorkerLifecycleError, match="worker_start_failed"):
            await coordinator.start(worker_request, actor="operator:test", at=NOW)

    with session_factory() as session:
        stored = ActionRepository(session).get(action.id)
        event_types = {
            event.event_type
            for event in AuditEventRepository(session).list_for_engagement(action.engagement_id)
        }
    assert stored is not None
    assert stored.entity.state is ActionState.WORKER_LOST
    assert "worker.start_failed" in event_types
    assert "worker.destroyed" not in event_types


async def test_collect_is_refused_for_a_worker_with_no_registry_binding(engine: Engine) -> None:
    seed_action(engine)
    session_factory = create_session_factory(engine)
    with session_factory.begin() as session:
        coordinator = ActionWorkerCoordinator(session, DisabledWorkerManager())
        with pytest.raises(WorkerLifecycleError, match="worker_action_binding_not_found"):
            await coordinator.collect("wrk_never_registered", at=NOW)


async def test_collect_refuses_when_the_manager_cannot_reattach_the_worker(
    engine: Engine,
) -> None:
    _engagement, action, worker_request = seed_action(engine)
    execution = _in_flight_execution(worker_request)
    session_factory = create_session_factory(engine)
    with session_factory.begin() as session:
        WorkerExecutionRepository(session).add(execution)

    with session_factory.begin() as session:
        coordinator = ActionWorkerCoordinator(session, DisabledWorkerManager())
        with pytest.raises(WorkerLifecycleError, match="worker_terminal_response_missing"):
            await coordinator.collect(execution.id, at=NOW + timedelta(minutes=1))

    with session_factory() as session:
        stored = ActionRepository(session).get(action.id)
        binding = WorkerExecutionRepository(session).get(execution.id)
    assert stored is not None
    assert stored.entity.state is ActionState.QUEUED
    assert binding is not None
    assert binding.entity.state is WorkerState.RUNNING


async def test_a_late_response_cannot_reopen_an_already_closed_action(engine: Engine) -> None:
    _engagement, action, worker_request = seed_action(engine)
    runtime = FakeRuntime()
    session_factory = create_session_factory(engine)
    with session_factory.begin() as session:
        coordinator = ActionWorkerCoordinator(
            session,
            LifecycleWorkerManager(runtime, clock=lambda: NOW),
        )
        handle = await coordinator.start(worker_request, actor="operator:test", at=NOW)
        await coordinator.cancel(handle.worker_id, actor="operator:test", at=NOW)
        with pytest.raises(WorkerLifecycleError, match="action_not_running"):
            await coordinator.collect(handle.worker_id, at=NOW + timedelta(seconds=1))

    with session_factory() as session:
        stored = ActionRepository(session).get(action.id)
        event_types = {
            event.event_type
            for event in AuditEventRepository(session).list_for_engagement(action.engagement_id)
        }
    assert stored is not None
    assert stored.entity.state is ActionState.CANCELLED
    assert "worker.collected" not in event_types


async def test_cancel_is_refused_for_a_worker_with_no_registry_binding(engine: Engine) -> None:
    seed_action(engine)
    session_factory = create_session_factory(engine)
    with session_factory.begin() as session:
        coordinator = ActionWorkerCoordinator(session, DisabledWorkerManager())
        with pytest.raises(WorkerLifecycleError, match="worker_action_binding_not_found"):
            await coordinator.cancel("wrk_never_registered", actor="operator:test", at=NOW)


async def test_cancel_cannot_close_an_action_a_second_time(engine: Engine) -> None:
    _engagement, action, worker_request = seed_action(engine)
    runtime = FakeRuntime()
    session_factory = create_session_factory(engine)
    with session_factory.begin() as session:
        coordinator = ActionWorkerCoordinator(
            session,
            LifecycleWorkerManager(runtime, clock=lambda: NOW),
        )
        handle = await coordinator.start(worker_request, actor="operator:test", at=NOW)
        await coordinator.cancel(handle.worker_id, actor="operator:test", at=NOW)
        with pytest.raises(WorkerLifecycleError, match="action_not_running"):
            await coordinator.cancel(handle.worker_id, actor="operator:test", at=NOW)

    with session_factory() as session:
        stored = ActionRepository(session).get(action.id)
        cancelled_events = [
            event
            for event in AuditEventRepository(session).list_for_engagement(action.engagement_id)
            if event.event_type == "worker.cancelled"
        ]
    assert stored is not None
    assert stored.entity.state is ActionState.CANCELLED
    assert len(cancelled_events) == 1
    assert runtime.calls == ["create", "start", "cancel", "destroy"]


def test_reconciliation_marks_a_worker_lost_when_its_action_row_is_gone(engine: Engine) -> None:
    engagement, _action, worker_request = seed_action(engine)
    execution = _in_flight_execution(
        worker_request,
        request_id="worker-request-orphan",
        action_id=new_action_id(),
    )
    session_factory = create_session_factory(engine)
    with session_factory.begin() as session:
        WorkerExecutionRepository(session).add(execution)

    with session_factory.begin() as session:
        reconciled = ActionWorkerCoordinator(
            session,
            DisabledWorkerManager(),
        ).reconcile_after_restart(at=NOW + timedelta(minutes=1))

    assert len(reconciled) == 1
    assert reconciled[0].state is WorkerState.LOST
    assert reconciled[0].error_code == "worker_recovery_unavailable"
    payloads = _payloads_for(engine, engagement.id, "worker.reconciled_lost")
    assert len(payloads) == 1
    assert payloads[0]["action_state"] == "missing"


def test_reconciliation_does_not_reopen_an_already_terminal_action(engine: Engine) -> None:
    engagement, action, worker_request = seed_action(engine)
    closed = replace(
        action,
        state=ActionState.SUCCEEDED,
        started_at=NOW,
        completed_at=NOW,
    )
    execution = _in_flight_execution(worker_request, state=WorkerState.STARTING)
    session_factory = create_session_factory(engine)
    with session_factory.begin() as session:
        ActionRepository(session).save(closed, expected_version=1)
        WorkerExecutionRepository(session).add(execution)

    with session_factory.begin() as session:
        reconciled = ActionWorkerCoordinator(
            session,
            DisabledWorkerManager(),
        ).reconcile_after_restart(at=NOW + timedelta(minutes=1))

    with session_factory() as session:
        stored = ActionRepository(session).get(action.id)
    assert len(reconciled) == 1
    assert reconciled[0].state is WorkerState.LOST
    assert stored is not None
    assert stored.entity.state is ActionState.SUCCEEDED
    payloads = _payloads_for(engine, engagement.id, "worker.reconciled_lost")
    assert payloads[0]["action_state"] == "succeeded"


async def test_a_worker_scope_wider_than_the_engagement_scope_is_refused(engine: Engine) -> None:
    _engagement, _action, worker_request = seed_action(engine)
    widened = worker_request.model_copy(
        update={
            "scope": WorkerScope(
                allowed_hostnames=("example.test", "intranet.example.test"),
                allowed_ports=(443,),
                allowed_schemes=("https",),
                allowed_paths=("/public",),
            )
        }
    )
    runtime = FakeRuntime()
    session_factory = create_session_factory(engine)
    with session_factory.begin() as session:
        coordinator = ActionWorkerCoordinator(session, LifecycleWorkerManager(runtime))
        with pytest.raises(WorkerLifecycleError, match="worker_request_scope_binding_mismatch"):
            await coordinator.start(widened, actor="operator:test", at=NOW)
    assert runtime.calls == []


async def test_start_is_refused_when_the_engagement_scope_is_missing(engine: Engine) -> None:
    engagement, _action, worker_request = seed_action(engine)
    session_factory = create_session_factory(engine)
    with session_factory.begin() as session:
        row = session.get(EngagementScopeRecord, engagement.id)
        assert row is not None
        session.delete(row)

    runtime = FakeRuntime()
    with session_factory.begin() as session:
        coordinator = ActionWorkerCoordinator(session, LifecycleWorkerManager(runtime))
        with pytest.raises(WorkerLifecycleError, match="scope_not_found"):
            await coordinator.start(worker_request, actor="operator:test", at=NOW)
    assert runtime.calls == []


async def test_a_capture_for_another_target_is_refused_without_persisting_evidence(
    engine: Engine,
) -> None:
    _engagement, action, worker_request = seed_action(engine)
    body = b"hello"
    # The path is inside scope, so only the action-target binding can refuse this.
    elsewhere = WorkerHttpCapture(
        method="GET",
        request_target="https://example.test:443/public/deeper",
        status_code=200,
        final_target="https://example.test:443/public/deeper",
        body_base64=base64.b64encode(body).decode(),
        body_sha256=hashlib.sha256(body).hexdigest(),
        captured_at=NOW,
        duration_ms=12,
    )
    manager = ScriptedWorkerManager(worker_request.request_id)
    session_factory = create_session_factory(engine)
    with session_factory.begin() as session:
        coordinator = ActionWorkerCoordinator(session, manager)
        handle = await coordinator.start(worker_request, actor="operator:test", at=NOW)
        manager.status_handle = replace(handle, state=WorkerState.COMPLETED, cleaned_up=True)
        manager.response = _capture_response(worker_request, capture=elsewhere)
        response = await coordinator.collect(handle.worker_id, at=NOW + timedelta(seconds=1))

    with session_factory() as session:
        stored = ActionRepository(session).get(action.id)
        evidence = EvidenceRepository(session).for_action(action.id)
    assert response.status is WorkerResultStatus.FAILED
    assert response.error_code == "worker_capture_binding_invalid"
    assert response.evidence_ids == ()
    assert stored is not None
    assert stored.entity.state is ActionState.FAILED
    assert evidence == ()


async def test_a_handle_for_another_worker_cannot_overwrite_the_registry_row(
    engine: Engine,
) -> None:
    _engagement, action, worker_request = seed_action(engine)
    evidence = Evidence(action_id=action.id, tool_name="fake", tool_version="1", digest="b" * 64)
    manager = ScriptedWorkerManager(worker_request.request_id)
    session_factory = create_session_factory(engine)
    with session_factory.begin() as session:
        coordinator = ActionWorkerCoordinator(session, manager)
        handle = await coordinator.start(worker_request, actor="operator:test", at=NOW)
        manager.status_handle = replace(
            handle,
            worker_id=new_worker_id(),
            state=WorkerState.COMPLETED,
            cleaned_up=True,
        )
        manager.response = _response(worker_request, WorkerResultStatus.SUCCEEDED, evidence.id)
        with pytest.raises(
            WorkerLifecycleError,
            match="worker_handle_registry_binding_mismatch",
        ):
            await coordinator.collect(handle.worker_id, at=NOW + timedelta(seconds=1))

    with session_factory() as session:
        stored = ActionRepository(session).get(action.id)
        binding = WorkerExecutionRepository(session).get(handle.worker_id)
    assert stored is not None
    assert stored.entity.state is ActionState.RUNNING
    assert binding is not None
    assert binding.entity.state is WorkerState.RUNNING


async def test_a_worker_that_cannot_be_destroyed_closes_the_action_as_worker_lost(
    engine: Engine,
) -> None:
    _engagement, action, worker_request = seed_action(engine)
    evidence = Evidence(
        action_id=action.id,
        tool_name="fake-worker",
        tool_version="1",
        digest="c" * 64,
        captured_at=NOW,
    )
    runtime = UndestroyableRuntime()
    runtime.response = _response(worker_request, WorkerResultStatus.SUCCEEDED, evidence.id)
    session_factory = create_session_factory(engine)
    with session_factory.begin() as session:
        EvidenceRepository(session).add(evidence)
        coordinator = ActionWorkerCoordinator(
            session,
            LifecycleWorkerManager(runtime, clock=lambda: NOW),
        )
        handle = await coordinator.start(worker_request, actor="operator:test", at=NOW)
        response = await coordinator.collect(handle.worker_id, at=NOW + timedelta(seconds=1))

    with session_factory() as session:
        stored = ActionRepository(session).get(action.id)
        binding = WorkerExecutionRepository(session).get(handle.worker_id)
    assert response.status is WorkerResultStatus.WORKER_ERROR
    assert response.error_code == "worker_cleanup_failed"
    assert stored is not None
    assert stored.entity.state is ActionState.WORKER_LOST
    assert binding is not None
    assert binding.entity.state is WorkerState.LOST
    assert not binding.entity.cleaned_up
    assert binding.entity.error_code == "worker_cleanup_failed"


@pytest.mark.parametrize(
    "drift",
    [
        {"engagement_id": new_engagement_id()},
        {"action_type": "exploit_attempt"},
        {"normalized_target": "https://example.test:443/elsewhere"},
        {"parameter_digest": "c" * 64},
        {"risk_level": RiskLevel.L2},
        {"approval_id": new_approval_id()},
        {"idempotency_key": "lifecycle-replayed"},
    ],
    ids=[
        "engagement_id",
        "action_type",
        "normalized_target",
        "parameter_digest",
        "risk_level",
        "approval_id",
        "idempotency_key",
    ],
)
async def test_a_worker_request_that_drifts_from_the_action_in_any_field_is_refused(
    engine: Engine,
    drift: dict[str, object],
) -> None:
    # Each field is a separate authority claim: the engagement the work is billed to, the
    # risk tier that decided whether an Approval was needed, the Approval itself, and the
    # replay guard. One test per field, because a single-field case would still pass with
    # any of the other seven comparisons deleted.
    _engagement, action, worker_request = seed_action(engine)
    runtime = FakeRuntime()
    session_factory = create_session_factory(engine)
    with session_factory.begin() as session:
        coordinator = ActionWorkerCoordinator(session, LifecycleWorkerManager(runtime))
        with pytest.raises(
            WorkerLifecycleError,
            match="worker_request_action_binding_mismatch",
        ):
            await coordinator.start(
                worker_request.model_copy(update=drift),
                actor="operator:test",
                at=NOW,
            )

    with session_factory() as session:
        stored = ActionRepository(session).get(action.id)
        binding = WorkerExecutionRepository(session).get_for_action(action.id)
    assert runtime.calls == []
    assert binding is None
    assert stored is not None
    assert stored.entity.state is ActionState.QUEUED


@pytest.mark.parametrize(
    ("reported", "expected"),
    [
        (WorkerResultStatus.FAILED, ActionState.FAILED),
        (WorkerResultStatus.TIMED_OUT, ActionState.TIMED_OUT),
        (WorkerResultStatus.CANCELLED, ActionState.CANCELLED),
        (WorkerResultStatus.POLICY_DENIED, ActionState.FAILED),
        (WorkerResultStatus.WORKER_ERROR, ActionState.WORKER_LOST),
    ],
    ids=["failed", "timed_out", "cancelled", "policy_denied", "worker_error"],
)
async def test_each_unsuccessful_worker_status_closes_the_action_in_its_own_state(
    engine: Engine,
    reported: WorkerResultStatus,
    expected: ActionState,
) -> None:
    # The status-to-state table is one dict literal, so line coverage says nothing about
    # the individual entries. Every one of these must be pinned: a worker that refused on
    # policy grounds, or crashed, must never leave an Action recorded as succeeded, and a
    # crashed worker must be distinguishable from a clean failure for reconciliation.
    _engagement, action, worker_request = seed_action(engine)
    manager = ScriptedWorkerManager(worker_request.request_id)
    session_factory = create_session_factory(engine)
    with session_factory.begin() as session:
        coordinator = ActionWorkerCoordinator(session, manager)
        handle = await coordinator.start(worker_request, actor="operator:test", at=NOW)
        manager.status_handle = replace(handle, state=WorkerState.COMPLETED, cleaned_up=True)
        manager.response = WorkerResponse(
            request_id=worker_request.request_id,
            engagement_id=worker_request.engagement_id,
            action_id=worker_request.action_id,
            status=reported,
            started_at=NOW,
            completed_at=NOW + timedelta(seconds=1),
            exit_code=1,
            error_code="worker_reported_failure",
        )
        response = await coordinator.collect(handle.worker_id, at=NOW + timedelta(seconds=1))

    with session_factory() as session:
        stored = ActionRepository(session).get(action.id)
        evidence = EvidenceRepository(session).for_action(action.id)
    assert response.status is reported
    assert stored is not None
    assert stored.entity.state is expected
    assert evidence == ()


@pytest.mark.parametrize(
    "forged",
    [
        {"request_id": "worker-request-never-registered"},
        {"engagement_id": new_engagement_id()},
        {"action_id": new_action_id()},
    ],
    ids=["request_id", "engagement_id", "action_id"],
)
async def test_a_response_naming_another_binding_cannot_close_this_action(
    engine: Engine,
    forged: dict[str, object],
) -> None:
    # Every decision after collect() reads an identity field off the response: the
    # evidence binding is checked against response.action_id and both audit events are
    # written under response.engagement_id. Without this refusal a worker naming somebody
    # else's action closes its own Action as SUCCEEDED holding no evidence, and the real
    # engagement's audit chain never records the collection.
    _engagement, action, worker_request = seed_action(engine)
    manager = ScriptedWorkerManager(worker_request.request_id)
    session_factory = create_session_factory(engine)
    with session_factory.begin() as session:
        coordinator = ActionWorkerCoordinator(session, manager)
        handle = await coordinator.start(worker_request, actor="operator:test", at=NOW)
        manager.status_handle = replace(handle, state=WorkerState.COMPLETED, cleaned_up=True)
        manager.response = _capture_response(worker_request).model_copy(update=forged)
        with pytest.raises(
            WorkerLifecycleError,
            match="worker_response_registry_binding_mismatch",
        ):
            await coordinator.collect(handle.worker_id, at=NOW + timedelta(seconds=1))

    with session_factory() as session:
        stored = ActionRepository(session).get(action.id)
        evidence = EvidenceRepository(session).for_action(action.id)
        event_types = {
            event.event_type
            for event in AuditEventRepository(session).list_for_engagement(action.engagement_id)
        }
    assert stored is not None
    assert stored.entity.state is ActionState.RUNNING
    assert evidence == ()
    assert "worker.collected" not in event_types
