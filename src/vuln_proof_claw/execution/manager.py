"""Disposable worker lifecycle with an injected, restricted runtime boundary."""

from __future__ import annotations

import asyncio
from collections.abc import Callable
from dataclasses import dataclass, field, replace
from datetime import UTC, datetime
from enum import StrEnum
from typing import Protocol

from vuln_proof_claw.domain.identifiers import new_identifier
from vuln_proof_claw.execution.protocol import (
    WorkerRequest,
    WorkerResponse,
    WorkerResultStatus,
)


class WorkerState(StrEnum):
    """Control-plane view of a disposable worker lifecycle."""

    QUEUED = "queued"
    STARTING = "starting"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    TIMED_OUT = "timed_out"
    CANCELLED = "cancelled"
    LOST = "lost"

    @property
    def terminal(self) -> bool:
        return self in {
            WorkerState.COMPLETED,
            WorkerState.FAILED,
            WorkerState.TIMED_OUT,
            WorkerState.CANCELLED,
            WorkerState.LOST,
        }


@dataclass(frozen=True, slots=True)
class WorkerHandle:
    """Safe lifecycle metadata; the privileged runtime reference stays internal."""

    worker_id: str
    request_id: str
    state: WorkerState
    created_at: datetime
    updated_at: datetime | None = None
    cleaned_up: bool = False
    error_code: str | None = None


class WorkerManagerError(Exception):
    """Base class for expected worker-manager failures."""


class WorkerExecutionUnavailableError(WorkerManagerError):
    """Raised while no explicitly configured execution adapter exists."""


class WorkerNotFoundError(WorkerManagerError):
    """Raised when a lifecycle operation references an unknown worker."""


class InvalidWorkerStateError(WorkerManagerError):
    """Raised when an operation is invalid for the current worker state."""


class WorkerRequestConflictError(WorkerManagerError):
    """Raised when a request identifier is replayed with changed protected input."""


class WorkerRuntime(Protocol):
    """Narrow privileged adapter implemented by a future isolated runtime service."""

    @property
    def identity(self) -> str:
        """Return an immutable runtime implementation or image identity."""

    async def create(self, request: WorkerRequest) -> str:
        """Create a stopped disposable worker and return an opaque runtime reference."""

    async def start(self, runtime_reference: str) -> None:
        """Start a previously created worker."""

    async def wait(self, runtime_reference: str) -> WorkerResponse:
        """Wait for a terminal protocol response."""

    async def cancel(self, runtime_reference: str) -> None:
        """Request termination of a running worker."""

    async def destroy(self, runtime_reference: str) -> None:
        """Destroy the worker and every per-action runtime resource."""


class WorkerManager(Protocol):
    """Privileged lifecycle boundary for already authorized requests."""

    @property
    def runtime_identity(self) -> str:
        """Return the immutable runtime identity included in audit records."""

    async def submit(self, request: WorkerRequest) -> WorkerHandle:
        """Create, but do not start, one disposable worker."""

    async def start(self, worker_id: str) -> WorkerHandle:
        """Start a created worker."""

    async def status(self, worker_id: str) -> WorkerHandle | None:
        """Return the current worker lifecycle state."""

    async def cancel(self, worker_id: str) -> WorkerHandle:
        """Cancel and destroy a non-terminal worker."""

    async def collect(self, worker_id: str) -> WorkerResponse | None:
        """Collect a terminal response and destroy the worker."""


@dataclass(slots=True)
class _ManagedWorker:
    request: WorkerRequest
    runtime_reference: str
    handle: WorkerHandle
    response: WorkerResponse | None = None
    lock: asyncio.Lock = field(default_factory=asyncio.Lock)
    collection_task: asyncio.Task[WorkerResponse] | None = None


def _utc_now() -> datetime:
    return datetime.now(UTC)


class LifecycleWorkerManager:
    """Process-local lifecycle manager that always attempts disposable cleanup."""

    def __init__(
        self,
        runtime: WorkerRuntime,
        *,
        clock: Callable[[], datetime] = _utc_now,
    ) -> None:
        self._runtime = runtime
        self._clock = clock
        self._workers: dict[str, _ManagedWorker] = {}
        self._request_index: dict[str, str] = {}
        self._lock = asyncio.Lock()

    @property
    def runtime_identity(self) -> str:
        return self._runtime.identity

    async def submit(self, request: WorkerRequest) -> WorkerHandle:
        async with self._lock:
            existing_id = self._request_index.get(request.request_id)
            if existing_id is not None:
                managed = self._workers[existing_id]
                if managed.request != request:
                    raise WorkerRequestConflictError("worker_request_id_conflict")
                return managed.handle

            runtime_reference = await self._runtime.create(request)
            if not runtime_reference.strip():
                raise WorkerManagerError("runtime_returned_empty_reference")
            timestamp = self._clock()
            worker_id = new_identifier()
            handle = WorkerHandle(
                worker_id=worker_id,
                request_id=request.request_id,
                state=WorkerState.STARTING,
                created_at=timestamp,
                updated_at=timestamp,
            )
            self._workers[worker_id] = _ManagedWorker(
                request=request,
                runtime_reference=runtime_reference,
                handle=handle,
            )
            self._request_index[request.request_id] = worker_id
            return handle

    async def start(self, worker_id: str) -> WorkerHandle:
        managed = self._required(worker_id)
        async with managed.lock:
            if managed.handle.state is WorkerState.RUNNING:
                return managed.handle
            if managed.handle.state is not WorkerState.STARTING:
                raise InvalidWorkerStateError("worker_not_startable")
            try:
                await self._runtime.start(managed.runtime_reference)
            except Exception as error:
                await self._cleanup(managed, error_code="worker_start_failed")
                raise WorkerManagerError("worker_start_failed") from error
            managed.handle = replace(
                managed.handle,
                state=WorkerState.RUNNING,
                updated_at=self._clock(),
            )
            return managed.handle

    async def status(self, worker_id: str) -> WorkerHandle | None:
        managed = self._workers.get(worker_id)
        return managed.handle if managed else None

    async def cancel(self, worker_id: str) -> WorkerHandle:
        managed = self._required(worker_id)
        async with managed.lock:
            if managed.handle.state.terminal:
                return managed.handle
            timestamp = self._clock()
            error_code: str | None = None
            try:
                await self._runtime.cancel(managed.runtime_reference)
            except Exception:  # noqa: BLE001 - cleanup still required
                error_code = "worker_cancel_failed"
            managed.response = WorkerResponse(
                request_id=managed.request.request_id,
                engagement_id=managed.request.engagement_id,
                action_id=managed.request.action_id,
                status=WorkerResultStatus.CANCELLED,
                started_at=managed.handle.updated_at or managed.handle.created_at,
                completed_at=timestamp,
                error_code=error_code or "worker_cancelled",
            )
            if managed.collection_task is not None and not managed.collection_task.done():
                managed.collection_task.cancel()
            await self._cleanup(
                managed,
                state=WorkerState.CANCELLED if error_code is None else WorkerState.LOST,
                error_code=error_code,
            )
            return managed.handle

    async def collect(self, worker_id: str) -> WorkerResponse | None:
        managed = self._required(worker_id)
        async with managed.lock:
            if managed.response is not None:
                return managed.response
            if managed.handle.state is not WorkerState.RUNNING:
                raise InvalidWorkerStateError("worker_not_collectable")
            if managed.collection_task is None:
                managed.collection_task = asyncio.create_task(self._collect_worker(managed))
            task = managed.collection_task
        return await asyncio.shield(task)

    async def _collect_worker(self, managed: _ManagedWorker) -> WorkerResponse:
        try:
            try:
                response = await asyncio.wait_for(
                    self._runtime.wait(managed.runtime_reference),
                    timeout=managed.request.limits.timeout_seconds,
                )
            except TimeoutError:
                response = await self._timeout_response(managed)
            except Exception:  # noqa: BLE001 - untrusted runtime failures become safe codes
                response = self._failure_response(managed, "worker_runtime_failure")
            if not self._response_matches(managed.request, response):
                response = self._failure_response(managed, "worker_response_binding_mismatch")
            async with managed.lock:
                if managed.response is not None:
                    return managed.response
                managed.response = response
                state = self._state_for_response(response)
                await self._cleanup(managed, state=state, error_code=response.error_code)
                return managed.response
        except asyncio.CancelledError:
            if managed.response is not None:
                return managed.response
            raise

    def _required(self, worker_id: str) -> _ManagedWorker:
        managed = self._workers.get(worker_id)
        if managed is None:
            raise WorkerNotFoundError("worker_not_found")
        return managed

    async def _timeout_response(self, managed: _ManagedWorker) -> WorkerResponse:
        try:
            await self._runtime.cancel(managed.runtime_reference)
        except Exception:  # noqa: BLE001 - destroy is still attempted
            return self._failure_response(managed, "worker_timeout_cancel_failed")
        return self._failure_response(
            managed,
            "worker_timed_out",
            status=WorkerResultStatus.TIMED_OUT,
        )

    def _failure_response(
        self,
        managed: _ManagedWorker,
        error_code: str,
        *,
        status: WorkerResultStatus = WorkerResultStatus.WORKER_ERROR,
    ) -> WorkerResponse:
        return WorkerResponse(
            request_id=managed.request.request_id,
            engagement_id=managed.request.engagement_id,
            action_id=managed.request.action_id,
            status=status,
            started_at=managed.handle.updated_at or managed.handle.created_at,
            completed_at=self._clock(),
            error_code=error_code,
        )

    async def _cleanup(
        self,
        managed: _ManagedWorker,
        *,
        state: WorkerState = WorkerState.LOST,
        error_code: str | None = None,
    ) -> None:
        cleanup_error = error_code
        cleaned_up = False
        try:
            await self._runtime.destroy(managed.runtime_reference)
            cleaned_up = True
        except Exception:  # noqa: BLE001 - cleanup failure is reflected in safe state
            cleanup_error = "worker_cleanup_failed"
            state = WorkerState.LOST
        managed.handle = replace(
            managed.handle,
            state=state,
            updated_at=self._clock(),
            cleaned_up=cleaned_up,
            error_code=cleanup_error,
        )
        if cleanup_error == "worker_cleanup_failed":
            managed.response = self._failure_response(managed, cleanup_error)

    @staticmethod
    def _response_matches(request: WorkerRequest, response: WorkerResponse) -> bool:
        return (
            response.protocol_version == request.protocol_version
            and response.request_id == request.request_id
            and response.engagement_id == request.engagement_id
            and response.action_id == request.action_id
        )

    @staticmethod
    def _state_for_response(response: WorkerResponse) -> WorkerState:
        return {
            WorkerResultStatus.SUCCEEDED: WorkerState.COMPLETED,
            WorkerResultStatus.FAILED: WorkerState.FAILED,
            WorkerResultStatus.TIMED_OUT: WorkerState.TIMED_OUT,
            WorkerResultStatus.CANCELLED: WorkerState.CANCELLED,
            WorkerResultStatus.POLICY_DENIED: WorkerState.FAILED,
            WorkerResultStatus.WORKER_ERROR: WorkerState.LOST,
        }[response.status]


class DisabledWorkerManager:
    """Fail closed until an explicitly configured runtime adapter exists."""

    @property
    def runtime_identity(self) -> str:
        return "disabled"

    async def submit(self, request: WorkerRequest) -> WorkerHandle:
        del request
        raise WorkerExecutionUnavailableError("worker execution adapter is not configured")

    async def start(self, worker_id: str) -> WorkerHandle:
        del worker_id
        raise WorkerExecutionUnavailableError("worker execution adapter is not configured")

    async def status(self, worker_id: str) -> WorkerHandle | None:
        del worker_id
        return None

    async def cancel(self, worker_id: str) -> WorkerHandle:
        del worker_id
        raise WorkerExecutionUnavailableError("worker execution adapter is not configured")

    async def collect(self, worker_id: str) -> WorkerResponse | None:
        del worker_id
        return None
