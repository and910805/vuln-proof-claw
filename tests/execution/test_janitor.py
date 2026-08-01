"""Orphan runtime janitor tests with a non-network inventory fake."""

from __future__ import annotations

from collections.abc import Generator
from datetime import datetime, timedelta
from pathlib import Path

import pytest
from sqlalchemy import Engine

from tests.execution.test_lifecycle import NOW, seed_action
from vuln_proof_claw.domain.enums import ActionState, WorkerState
from vuln_proof_claw.domain.identifiers import WorkerId
from vuln_proof_claw.domain.models import WorkerExecution
from vuln_proof_claw.execution.janitor import (
    OrphanRuntimeJanitor,
    RuntimeJanitorError,
    recover_runtime_after_restart,
)
from vuln_proof_claw.execution.manager import DisabledWorkerManager, RuntimeResource
from vuln_proof_claw.execution.protocol import WorkerRequest, WorkerResponse
from vuln_proof_claw.persistence.base import Base
from vuln_proof_claw.persistence.repositories import (
    ActionRepository,
    AuditEventRepository,
    ConcurrentUpdateError,
    WorkerExecutionRepository,
)
from vuln_proof_claw.persistence.session import create_engine, create_session_factory

RUNTIME_IDENTITY = "fake-runtime@sha256:janitor"


class InventoryRuntime:
    identity = RUNTIME_IDENTITY

    def __init__(self, resources: tuple[RuntimeResource, ...] = ()) -> None:
        self.resources = resources
        self.destroyed: list[str] = []
        self.destroy_errors: set[str] = set()
        self.inventory_error: Exception | None = None

    async def create(self, request: WorkerRequest, *, worker_id: WorkerId) -> str:
        del request, worker_id
        raise AssertionError("janitor must not create resources")

    async def start(self, runtime_reference: str) -> None:
        del runtime_reference
        raise AssertionError("janitor must not start resources")

    async def wait(self, runtime_reference: str) -> WorkerResponse:
        del runtime_reference
        raise AssertionError("janitor must not wait for resources")

    async def cancel(self, runtime_reference: str) -> None:
        del runtime_reference
        raise AssertionError("janitor must not cancel resources")

    async def destroy(self, runtime_reference: str) -> None:
        if runtime_reference in self.destroy_errors:
            raise RuntimeError("private runtime failure")
        self.destroyed.append(runtime_reference)

    async def list_resources(self) -> tuple[RuntimeResource, ...]:
        if self.inventory_error is not None:
            raise self.inventory_error
        return self.resources


@pytest.fixture
def engine(tmp_path: Path) -> Generator[Engine, None, None]:
    result = create_engine(f"sqlite:///{tmp_path / 'janitor.db'}", pool_pre_ping=False)
    Base.metadata.create_all(result)
    yield result
    result.dispose()


def _execution(
    engine: Engine,
    *,
    state: WorkerState,
    cleaned_up: bool = False,
    runtime_identity: str = RUNTIME_IDENTITY,
) -> WorkerExecution:
    engagement, action, request = seed_action(engine)
    execution = WorkerExecution(
        request_id=request.request_id,
        engagement_id=engagement.id,
        action_id=action.id,
        runtime_identity=runtime_identity,
        state=state,
        cleaned_up=cleaned_up,
        created_at=NOW - timedelta(minutes=10),
        updated_at=NOW - timedelta(minutes=1),
    )
    session_factory = create_session_factory(engine)
    with session_factory.begin() as session:
        WorkerExecutionRepository(session).add(execution)
    return execution


def _resource(
    worker_id: WorkerId,
    request_id: str,
    *,
    reference: str = "runtime-secret-1",
    created_at: datetime = NOW - timedelta(minutes=10),
) -> RuntimeResource:
    return RuntimeResource(
        worker_id=worker_id,
        request_id=request_id,
        reference=reference,
        created_at=created_at,
    )


async def test_terminal_registry_resource_is_destroyed_and_marked_clean(engine: Engine) -> None:
    execution = _execution(engine, state=WorkerState.LOST)
    resource = _resource(execution.id, execution.request_id)
    runtime = InventoryRuntime((resource,))
    session_factory = create_session_factory(engine)

    with session_factory.begin() as session:
        sweep = await OrphanRuntimeJanitor(session, runtime, clock=lambda: NOW).sweep()

    with session_factory() as session:
        stored = WorkerExecutionRepository(session).get(execution.id)
        events = AuditEventRepository(session).list_for_engagement(execution.engagement_id)
    assert sweep.destroyed_count == 1
    assert sweep.failed_count == 0
    assert sweep.outcomes[0].reason == "terminal_registry"
    assert runtime.destroyed == ["runtime-secret-1"]
    assert stored is not None
    assert stored.entity.cleaned_up
    assert "worker.janitor_destroyed" in {event.event_type for event in events}
    assert "runtime-secret-1" not in repr(sweep)
    assert "runtime-secret-1" not in repr(resource)


async def test_restart_recovery_marks_live_work_lost_before_destroying_resource(
    engine: Engine,
) -> None:
    execution = _execution(engine, state=WorkerState.RUNNING)
    runtime = InventoryRuntime((_resource(execution.id, execution.request_id),))
    session_factory = create_session_factory(engine)

    with session_factory.begin() as session:
        recovery = await recover_runtime_after_restart(
            session,
            DisabledWorkerManager(),
            runtime,
            at=NOW,
        )

    with session_factory() as session:
        stored_execution = WorkerExecutionRepository(session).get(execution.id)
        stored_action = ActionRepository(session).get(execution.action_id)
    assert len(recovery.reconciled) == 1
    assert recovery.sweep.destroyed_count == 1
    assert recovery.sweep.outcomes[0].reason == "terminal_registry"
    assert stored_execution is not None
    assert stored_execution.entity.state is WorkerState.LOST
    assert stored_execution.entity.cleaned_up
    assert stored_action is not None
    assert stored_action.entity.state is ActionState.WORKER_LOST


async def test_destroyed_resource_reports_registry_version_conflict_safely(
    engine: Engine,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    execution = _execution(engine, state=WorkerState.LOST)
    runtime = InventoryRuntime((_resource(execution.id, execution.request_id),))
    session_factory = create_session_factory(engine)

    def conflict(*args: object, **kwargs: object) -> None:
        del args, kwargs
        raise ConcurrentUpdateError

    monkeypatch.setattr(WorkerExecutionRepository, "save", conflict)
    with session_factory.begin() as session:
        sweep = await OrphanRuntimeJanitor(session, runtime, clock=lambda: NOW).sweep()

    assert sweep.destroyed_count == 1
    assert sweep.outcomes[0].reason == "registry_update_conflict"
    assert runtime.destroyed == ["runtime-secret-1"]
    assert "runtime-secret-1" not in repr(sweep)


async def test_live_registry_resource_is_never_destroyed(engine: Engine) -> None:
    execution = _execution(engine, state=WorkerState.RUNNING)
    runtime = InventoryRuntime((_resource(execution.id, execution.request_id),))
    session_factory = create_session_factory(engine)

    with session_factory.begin() as session:
        sweep = await OrphanRuntimeJanitor(
            session,
            runtime,
            grace_period=timedelta(0),
            clock=lambda: NOW,
        ).sweep()

    assert sweep.skipped_count == 1
    assert sweep.outcomes[0].reason == "in_flight"
    assert runtime.destroyed == []


async def test_unregistered_resource_observes_grace_period_then_is_destroyed(
    engine: Engine,
) -> None:
    worker_id = WorkerId("00000000-0000-7000-8000-000000000099")
    resource = _resource(worker_id, "orphan-request", created_at=NOW - timedelta(minutes=2))
    runtime = InventoryRuntime((resource,))
    session_factory = create_session_factory(engine)

    with session_factory.begin() as session:
        early = await OrphanRuntimeJanitor(session, runtime, clock=lambda: NOW).sweep()
    with session_factory.begin() as session:
        late = await OrphanRuntimeJanitor(
            session,
            runtime,
            clock=lambda: NOW + timedelta(minutes=4),
        ).sweep()

    assert early.outcomes[0].reason == "grace_period"
    assert late.outcomes[0].reason == "registry_missing"
    assert runtime.destroyed == ["runtime-secret-1"]


async def test_mismatched_labels_destroy_resource_without_mutating_registry(
    engine: Engine,
) -> None:
    execution = _execution(engine, state=WorkerState.LOST)
    resource = _resource(execution.id, "different-request")
    runtime = InventoryRuntime((resource,))
    session_factory = create_session_factory(engine)

    with session_factory.begin() as session:
        sweep = await OrphanRuntimeJanitor(session, runtime, clock=lambda: NOW).sweep()

    with session_factory() as session:
        stored = WorkerExecutionRepository(session).get(execution.id)
    assert sweep.outcomes[0].reason == "registry_binding_mismatch"
    assert stored is not None
    assert not stored.entity.cleaned_up


async def test_runtime_identity_mismatch_is_fail_closed(engine: Engine) -> None:
    execution = _execution(
        engine,
        state=WorkerState.LOST,
        runtime_identity="different-runtime@sha256:value",
    )
    session_factory = create_session_factory(engine)
    runtime = InventoryRuntime((_resource(execution.id, execution.request_id),))
    with session_factory.begin() as session:
        sweep = await OrphanRuntimeJanitor(session, runtime, clock=lambda: NOW).sweep()

    assert sweep.outcomes[0].reason == "runtime_identity_mismatch"
    assert runtime.destroyed == ["runtime-secret-1"]


async def test_cleanup_failure_is_safe_and_retryable(engine: Engine) -> None:
    execution = _execution(engine, state=WorkerState.LOST)
    runtime = InventoryRuntime((_resource(execution.id, execution.request_id),))
    runtime.destroy_errors.add("runtime-secret-1")
    session_factory = create_session_factory(engine)

    with session_factory.begin() as session:
        sweep = await OrphanRuntimeJanitor(session, runtime, clock=lambda: NOW).sweep()

    with session_factory() as session:
        stored = WorkerExecutionRepository(session).get(execution.id)
        events = AuditEventRepository(session).list_for_engagement(execution.engagement_id)
    assert sweep.failed_count == 1
    assert sweep.outcomes[0].reason == "cleanup_failed"
    assert "private runtime failure" not in repr(sweep)
    assert stored is not None
    assert not stored.entity.cleaned_up
    assert "worker.janitor_cleanup_failed" in {event.event_type for event in events}


async def test_duplicate_inventory_reference_is_destroyed_only_once(engine: Engine) -> None:
    worker_id = WorkerId("00000000-0000-7000-8000-000000000099")
    resource = _resource(worker_id, "orphan-request")
    runtime = InventoryRuntime((resource, resource))
    session_factory = create_session_factory(engine)

    with session_factory.begin() as session:
        sweep = await OrphanRuntimeJanitor(
            session,
            runtime,
            grace_period=timedelta(0),
            clock=lambda: NOW,
        ).sweep()

    assert sweep.destroyed_count == 1
    assert sweep.skipped_count == 1
    assert runtime.destroyed == ["runtime-secret-1"]


async def test_inventory_and_clock_failures_return_safe_errors(engine: Engine) -> None:
    session_factory = create_session_factory(engine)
    runtime = InventoryRuntime()
    runtime.inventory_error = RuntimeError("socket path")
    with (
        session_factory.begin() as session,
        pytest.raises(RuntimeJanitorError, match="worker_runtime_inventory_failed"),
    ):
        await OrphanRuntimeJanitor(session, runtime, clock=lambda: NOW).sweep()

    runtime.inventory_error = None
    with (
        session_factory.begin() as session,
        pytest.raises(RuntimeJanitorError, match="janitor_clock_must_be_timezone_aware"),
    ):
        await OrphanRuntimeJanitor(
            session,
            runtime,
            clock=lambda: datetime(2026, 8, 2),
        ).sweep()


def test_runtime_resource_rejects_empty_or_naive_metadata() -> None:
    worker_id = WorkerId("00000000-0000-7000-8000-000000000099")
    with pytest.raises(ValueError, match="request_id"):
        _resource(worker_id, " ")
    with pytest.raises(ValueError, match="reference"):
        _resource(worker_id, "request", reference=" ")
    with pytest.raises(ValueError, match="timezone-aware"):
        _resource(worker_id, "request", created_at=datetime(2026, 8, 2))
