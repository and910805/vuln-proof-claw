"""Worker lifecycle interface without target-facing execution."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from enum import StrEnum
from typing import Protocol

from vuln_proof_claw.execution.protocol import WorkerRequest, WorkerResponse


class WorkerState(StrEnum):
    """Control-plane view of a disposable worker lifecycle."""

    QUEUED = "queued"
    STARTING = "starting"
    RUNNING = "running"
    COMPLETED = "completed"
    CANCELLED = "cancelled"
    LOST = "lost"


@dataclass(frozen=True, slots=True)
class WorkerHandle:
    """Opaque handle returned after a worker request is accepted."""

    worker_id: str
    request_id: str
    state: WorkerState
    created_at: datetime


class WorkerManagerError(Exception):
    """Base class for expected worker-manager failures."""


class WorkerExecutionUnavailableError(WorkerManagerError):
    """Raised while the Phase 0 manager has no execution adapter."""


class WorkerManager(Protocol):
    """Privileged lifecycle boundary implemented by a future runtime adapter."""

    async def submit(self, request: WorkerRequest) -> WorkerHandle:
        """Create a disposable worker for an already authorized request."""

    async def status(self, worker_id: str) -> WorkerHandle | None:
        """Return the current worker lifecycle state."""

    async def cancel(self, worker_id: str) -> WorkerHandle:
        """Request cancellation without performing target-facing work."""

    async def collect(self, worker_id: str) -> WorkerResponse | None:
        """Collect a terminal protocol response."""


class DisabledWorkerManager:
    """Fail closed until an explicitly configured runtime adapter exists."""

    async def submit(self, request: WorkerRequest) -> WorkerHandle:
        del request
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
