"""Disposable lifecycle manager tests using a non-network fake runtime."""

from __future__ import annotations

import asyncio
from datetime import UTC, datetime, timedelta

import pytest

from tests.execution.test_protocol import http_capture, request
from vuln_proof_claw.domain.identifiers import EvidenceId, WorkerId
from vuln_proof_claw.execution.manager import (
    InvalidWorkerStateError,
    LifecycleWorkerManager,
    RuntimeResource,
    WorkerManagerError,
    WorkerNotFoundError,
    WorkerRequestConflictError,
    WorkerState,
)
from vuln_proof_claw.execution.protocol import (
    WorkerHttpCapture,
    WorkerRequest,
    WorkerResponse,
    WorkerResultStatus,
)

NOW = datetime(2026, 8, 1, 12, 0, tzinfo=UTC)


class FakeRuntime:
    identity = "fake-runtime@sha256:test"

    def __init__(self, response: WorkerResponse | None = None) -> None:
        worker_request = request()
        self.response = response or WorkerResponse(
            request_id=worker_request.request_id,
            engagement_id=worker_request.engagement_id,
            action_id=worker_request.action_id,
            status=WorkerResultStatus.SUCCEEDED,
            started_at=NOW,
            completed_at=NOW + timedelta(seconds=1),
            evidence_ids=(EvidenceId("00000000-0000-7000-8000-000000000004"),),
            exit_code=0,
        )
        self.calls: list[str] = []
        self.start_error: Exception | None = None
        self.wait_error: Exception | None = None
        self.destroy_error: Exception | None = None
        self.wait_started = asyncio.Event()
        self.wait_release: asyncio.Event | None = None

    async def create(self, worker_request: WorkerRequest, *, worker_id: WorkerId) -> str:
        del worker_request
        self.worker_id = worker_id
        self.calls.append("create")
        return "runtime-reference-1"

    async def list_resources(self) -> tuple[RuntimeResource, ...]:
        return ()

    async def start(self, runtime_reference: str) -> None:
        assert runtime_reference == "runtime-reference-1"
        self.calls.append("start")
        if self.start_error is not None:
            raise self.start_error

    async def wait(self, runtime_reference: str) -> WorkerResponse:
        assert runtime_reference == "runtime-reference-1"
        self.calls.append("wait")
        self.wait_started.set()
        if self.wait_release is not None:
            await self.wait_release.wait()
        if self.wait_error is not None:
            raise self.wait_error
        return self.response

    async def cancel(self, runtime_reference: str) -> None:
        assert runtime_reference == "runtime-reference-1"
        self.calls.append("cancel")

    async def destroy(self, runtime_reference: str) -> None:
        assert runtime_reference == "runtime-reference-1"
        self.calls.append("destroy")
        if self.destroy_error is not None:
            raise self.destroy_error


def manager(runtime: FakeRuntime) -> LifecycleWorkerManager:
    return LifecycleWorkerManager(runtime, clock=lambda: NOW)


async def test_successful_worker_is_created_started_collected_and_destroyed_once() -> None:
    runtime = FakeRuntime()
    lifecycle = manager(runtime)

    submitted = await lifecycle.submit(request())
    replayed = await lifecycle.submit(request())
    running = await lifecycle.start(submitted.worker_id)
    response = await lifecycle.collect(submitted.worker_id)
    cached = await lifecycle.collect(submitted.worker_id)
    terminal = await lifecycle.status(submitted.worker_id)

    assert replayed == submitted
    assert runtime.worker_id == submitted.worker_id
    assert submitted.state is WorkerState.STARTING
    assert running.state is WorkerState.RUNNING
    assert response is not None
    assert response.status is WorkerResultStatus.SUCCEEDED
    assert cached == response
    assert terminal is not None
    assert terminal.state is WorkerState.COMPLETED
    assert terminal.cleaned_up
    assert runtime.calls == ["create", "start", "wait", "destroy"]


async def test_request_id_replay_rejects_changed_request() -> None:
    lifecycle = manager(FakeRuntime())
    original = request()
    changed = original.model_copy(update={"action_type": "password_test"})
    await lifecycle.submit(original)

    with pytest.raises(WorkerRequestConflictError, match="request_id_conflict"):
        await lifecycle.submit(changed)


async def test_timeout_cancels_and_destroys_worker() -> None:
    runtime = FakeRuntime()
    runtime.wait_error = TimeoutError()
    lifecycle = manager(runtime)
    handle = await lifecycle.submit(request())
    await lifecycle.start(handle.worker_id)

    response = await lifecycle.collect(handle.worker_id)
    terminal = await lifecycle.status(handle.worker_id)

    assert response is not None
    assert response.status is WorkerResultStatus.TIMED_OUT
    assert response.error_code == "worker_timed_out"
    assert terminal is not None
    assert terminal.state is WorkerState.TIMED_OUT
    assert terminal.cleaned_up
    assert runtime.calls == ["create", "start", "wait", "cancel", "destroy"]


async def test_response_binding_mismatch_fails_closed() -> None:
    worker_request = request()
    mismatched = WorkerResponse(
        request_id="different-request",
        engagement_id=worker_request.engagement_id,
        action_id=worker_request.action_id,
        status=WorkerResultStatus.SUCCEEDED,
        started_at=NOW,
        completed_at=NOW,
        evidence_ids=(EvidenceId("00000000-0000-7000-8000-000000000004"),),
    )
    runtime = FakeRuntime(mismatched)
    lifecycle = manager(runtime)
    handle = await lifecycle.submit(worker_request)
    await lifecycle.start(handle.worker_id)

    response = await lifecycle.collect(handle.worker_id)
    terminal = await lifecycle.status(handle.worker_id)

    assert response is not None
    assert response.status is WorkerResultStatus.WORKER_ERROR
    assert response.error_code == "worker_response_binding_mismatch"
    assert terminal is not None
    assert terminal.state is WorkerState.LOST
    assert terminal.cleaned_up


@pytest.mark.parametrize(
    "capture",
    [
        http_capture(
            request_target="https://other.test:443/api/upload",
            final_target="https://other.test:443/api/upload",
        ),
        http_capture(duration_ms=300_001),
    ],
    ids=("target", "duration"),
)
async def test_inline_capture_binding_mismatch_fails_before_persistence(
    capture: WorkerHttpCapture,
) -> None:
    worker_request = request()
    inline_response = WorkerResponse(
        request_id=worker_request.request_id,
        engagement_id=worker_request.engagement_id,
        action_id=worker_request.action_id,
        status=WorkerResultStatus.SUCCEEDED,
        started_at=capture.captured_at,
        completed_at=capture.captured_at + timedelta(minutes=6),
        http_captures=(capture,),
        exit_code=0,
    )
    runtime = FakeRuntime(inline_response)
    lifecycle = manager(runtime)
    handle = await lifecycle.submit(worker_request)
    await lifecycle.start(handle.worker_id)

    response = await lifecycle.collect(handle.worker_id)

    assert response is not None
    assert response.status is WorkerResultStatus.WORKER_ERROR
    assert response.error_code == "worker_response_binding_mismatch"


async def test_start_and_cleanup_failures_are_safe_terminal_states() -> None:
    start_runtime = FakeRuntime()
    start_runtime.start_error = RuntimeError("unsafe internal detail")
    start_lifecycle = manager(start_runtime)
    start_handle = await start_lifecycle.submit(request())

    with pytest.raises(WorkerManagerError, match="worker_start_failed"):
        await start_lifecycle.start(start_handle.worker_id)
    start_terminal = await start_lifecycle.status(start_handle.worker_id)
    assert start_terminal is not None
    assert start_terminal.state is WorkerState.LOST
    assert start_terminal.cleaned_up
    assert "unsafe internal detail" not in str(start_terminal)

    cleanup_runtime = FakeRuntime()
    cleanup_runtime.destroy_error = RuntimeError("runtime path")
    cleanup_lifecycle = manager(cleanup_runtime)
    cleanup_handle = await cleanup_lifecycle.submit(request())
    await cleanup_lifecycle.start(cleanup_handle.worker_id)
    response = await cleanup_lifecycle.collect(cleanup_handle.worker_id)
    cleanup_terminal = await cleanup_lifecycle.status(cleanup_handle.worker_id)
    assert response is not None
    assert response.error_code == "worker_cleanup_failed"
    assert cleanup_terminal is not None
    assert cleanup_terminal.state is WorkerState.LOST
    assert not cleanup_terminal.cleaned_up


async def test_cancel_interrupts_collection_and_cleanup_remains_single_shot() -> None:
    runtime = FakeRuntime()
    runtime.wait_release = asyncio.Event()
    lifecycle = manager(runtime)
    handle = await lifecycle.submit(request())
    await lifecycle.start(handle.worker_id)
    collection = asyncio.create_task(lifecycle.collect(handle.worker_id))
    await runtime.wait_started.wait()

    cancelled = await lifecycle.cancel(handle.worker_id)
    response = await collection

    assert cancelled.state is WorkerState.CANCELLED
    assert cancelled.cleaned_up
    assert response is not None
    assert response.status is WorkerResultStatus.CANCELLED
    assert runtime.calls == ["create", "start", "wait", "cancel", "destroy"]


async def test_unknown_and_invalid_lifecycle_operations_are_rejected() -> None:
    lifecycle = manager(FakeRuntime())
    with pytest.raises(WorkerNotFoundError, match="worker_not_found"):
        await lifecycle.start("missing")

    handle = await lifecycle.submit(request())
    with pytest.raises(InvalidWorkerStateError, match="not_collectable"):
        await lifecycle.collect(handle.worker_id)

    cancelled = await lifecycle.cancel(handle.worker_id)
    assert await lifecycle.cancel(handle.worker_id) == cancelled
