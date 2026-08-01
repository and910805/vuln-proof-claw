"""Durable Action-to-Worker lifecycle integration tests."""

from __future__ import annotations

from collections.abc import Generator
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
from sqlalchemy import Engine

from vuln_proof_claw.domain.enums import ActionState, RiskLevel, WorkerState
from vuln_proof_claw.domain.identifiers import EvidenceId
from vuln_proof_claw.domain.models import (
    Action,
    Engagement,
    Evidence,
    Flow,
    Project,
    Task,
    WorkerExecution,
)
from vuln_proof_claw.execution.lifecycle import ActionWorkerCoordinator, WorkerLifecycleError
from vuln_proof_claw.execution.manager import DisabledWorkerManager, LifecycleWorkerManager
from vuln_proof_claw.execution.protocol import (
    WorkerLimits,
    WorkerRequest,
    WorkerResponse,
    WorkerResultStatus,
    WorkerScope,
)
from vuln_proof_claw.persistence.base import Base
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
DIGEST = "a" * 64


class FakeRuntime:
    identity = "fake-runtime@sha256:lifecycle"

    def __init__(self) -> None:
        self.response: WorkerResponse | None = None
        self.calls: list[str] = []
        self.start_error: Exception | None = None

    async def create(self, request: WorkerRequest) -> str:
        del request
        self.calls.append("create")
        return "runtime-1"

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
    action = Action(
        engagement_id=engagement.id,
        task_id=task.id,
        action_type="public_page_read",
        normalized_target="https://example.test:443/public",
        parameter_digest=DIGEST,
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
