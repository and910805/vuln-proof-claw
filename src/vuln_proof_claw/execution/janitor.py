"""Reconcile and remove disposable runtime resources left behind after failures."""

from __future__ import annotations

import asyncio
from collections.abc import Callable
from dataclasses import dataclass, replace
from datetime import UTC, datetime, timedelta
from enum import StrEnum

from sqlalchemy.orm import Session

from vuln_proof_claw.audit import record_audit_event
from vuln_proof_claw.domain.models import WorkerExecution
from vuln_proof_claw.execution.lifecycle import ActionWorkerCoordinator
from vuln_proof_claw.execution.manager import RuntimeResource, WorkerManager, WorkerRuntime
from vuln_proof_claw.persistence.repositories import (
    ConcurrentUpdateError,
    Stored,
    WorkerExecutionRepository,
)

_JANITOR_ACTOR = "system:runtime-janitor"


class RuntimeJanitorError(Exception):
    """Safe error raised when runtime inventory cannot be inspected."""


class JanitorStatus(StrEnum):
    """Public, non-privileged outcome for one inventoried runtime resource."""

    DESTROYED = "destroyed"
    SKIPPED = "skipped"
    FAILED = "failed"


@dataclass(frozen=True, slots=True)
class JanitorOutcome:
    """Safe cleanup result that never exposes a privileged runtime reference."""

    worker_id: str
    request_id: str
    status: JanitorStatus
    reason: str


@dataclass(frozen=True, slots=True)
class JanitorSweep:
    """Deterministic summary for one non-overlapping inventory sweep."""

    runtime_identity: str
    started_at: datetime
    completed_at: datetime
    outcomes: tuple[JanitorOutcome, ...]

    @property
    def destroyed_count(self) -> int:
        return sum(outcome.status is JanitorStatus.DESTROYED for outcome in self.outcomes)

    @property
    def failed_count(self) -> int:
        return sum(outcome.status is JanitorStatus.FAILED for outcome in self.outcomes)

    @property
    def skipped_count(self) -> int:
        return sum(outcome.status is JanitorStatus.SKIPPED for outcome in self.outcomes)


@dataclass(frozen=True, slots=True)
class RuntimeRecovery:
    """Combined durable-registry reconciliation and runtime cleanup result."""

    reconciled: tuple[WorkerExecution, ...]
    sweep: JanitorSweep


def _utc_now() -> datetime:
    return datetime.now(UTC)


class OrphanRuntimeJanitor:
    """Destroy owned terminal or unregistered resources without touching live work."""

    def __init__(
        self,
        session: Session,
        runtime: WorkerRuntime,
        *,
        grace_period: timedelta = timedelta(minutes=5),
        clock: Callable[[], datetime] = _utc_now,
    ) -> None:
        if grace_period < timedelta(0):
            raise ValueError("grace_period must not be negative")
        self._session = session
        self._runtime = runtime
        self._grace_period = grace_period
        self._clock = clock
        self._lock = asyncio.Lock()

    async def sweep(self) -> JanitorSweep:
        """Inspect owned resources once and return only safe cleanup metadata."""
        async with self._lock:
            started_at = self._aware_now()
            try:
                resources = await self._runtime.list_resources()
            except Exception as error:
                raise RuntimeJanitorError("worker_runtime_inventory_failed") from error

            outcomes: list[JanitorOutcome] = []
            seen_references: set[str] = set()
            for resource in sorted(
                resources,
                key=lambda item: (item.created_at, str(item.worker_id), item.request_id),
            ):
                if resource.reference in seen_references:
                    outcomes.append(
                        self._outcome(resource, JanitorStatus.SKIPPED, "duplicate_reference")
                    )
                    continue
                seen_references.add(resource.reference)
                outcomes.append(await self._inspect(resource, at=started_at))

            return JanitorSweep(
                runtime_identity=self._runtime.identity,
                started_at=started_at,
                completed_at=self._aware_now(),
                outcomes=tuple(outcomes),
            )

    async def _inspect(self, resource: RuntimeResource, *, at: datetime) -> JanitorOutcome:
        repository = WorkerExecutionRepository(self._session)
        by_id = repository.get(resource.worker_id)
        by_request = repository.get_for_request(resource.request_id)
        stored = self._bound_execution(by_id, by_request)

        if stored is None:
            reason = (
                "registry_missing"
                if by_id is None and by_request is None
                else "registry_binding_mismatch"
            )
            return await self._inspect_unbound(
                resource,
                reason=reason,
                audit_execution=by_id,
                at=at,
            )

        execution = stored.entity
        if execution.runtime_identity != self._runtime.identity:
            return await self._inspect_unbound(
                resource,
                reason="runtime_identity_mismatch",
                audit_execution=stored,
                at=at,
            )

        if not execution.state.terminal:
            return self._outcome(resource, JanitorStatus.SKIPPED, "in_flight")

        reason = "stale_registry_claim" if execution.cleaned_up else "terminal_registry"
        return await self._destroy_bound(resource, stored=stored, reason=reason, at=at)

    async def _destroy_bound(
        self,
        resource: RuntimeResource,
        *,
        stored: Stored[WorkerExecution],
        reason: str,
        at: datetime,
    ) -> JanitorOutcome:
        execution = stored.entity
        try:
            await self._runtime.destroy(resource.reference)
        except Exception:  # noqa: BLE001 - runtime details must not escape
            self._audit(stored, "worker.janitor_cleanup_failed", "cleanup_failed", at=at)
            return self._outcome(resource, JanitorStatus.FAILED, "cleanup_failed")

        if not execution.cleaned_up:
            updated = replace(
                execution,
                cleaned_up=True,
                updated_at=max(at, execution.updated_at),
            )
            try:
                stored = WorkerExecutionRepository(self._session).save(
                    updated,
                    expected_version=stored.version,
                )
            except ConcurrentUpdateError:
                self._audit(
                    stored,
                    "worker.janitor_registry_update_failed",
                    "registry_update_conflict",
                    at=at,
                )
                return self._outcome(
                    resource,
                    JanitorStatus.DESTROYED,
                    "registry_update_conflict",
                )
        self._audit(stored, "worker.janitor_destroyed", reason, at=at)
        return self._outcome(resource, JanitorStatus.DESTROYED, reason)

    async def _inspect_unbound(
        self,
        resource: RuntimeResource,
        *,
        reason: str,
        audit_execution: Stored[WorkerExecution] | None,
        at: datetime,
    ) -> JanitorOutcome:
        if not self._past_grace_period(resource, at=at):
            return self._outcome(resource, JanitorStatus.SKIPPED, "grace_period")
        return await self._destroy_unbound(
            resource,
            reason=reason,
            audit_execution=audit_execution,
            at=at,
        )

    async def _destroy_unbound(
        self,
        resource: RuntimeResource,
        *,
        reason: str,
        audit_execution: Stored[WorkerExecution] | None,
        at: datetime,
    ) -> JanitorOutcome:
        try:
            await self._runtime.destroy(resource.reference)
        except Exception:  # noqa: BLE001 - runtime details must not escape
            if audit_execution is not None:
                self._audit(
                    audit_execution,
                    "worker.janitor_cleanup_failed",
                    "cleanup_failed",
                    at=at,
                )
            return self._outcome(resource, JanitorStatus.FAILED, "cleanup_failed")
        if audit_execution is not None:
            self._audit(audit_execution, "worker.janitor_destroyed", reason, at=at)
        return self._outcome(resource, JanitorStatus.DESTROYED, reason)

    @staticmethod
    def _bound_execution(
        by_id: Stored[WorkerExecution] | None,
        by_request: Stored[WorkerExecution] | None,
    ) -> Stored[WorkerExecution] | None:
        if by_id is None or by_request is None:
            return None
        if by_id.entity.id != by_request.entity.id:
            return None
        return by_id

    def _past_grace_period(self, resource: RuntimeResource, *, at: datetime) -> bool:
        return at >= resource.created_at + self._grace_period

    def _audit(
        self,
        stored: Stored[WorkerExecution],
        event_type: str,
        reason: str,
        *,
        at: datetime,
    ) -> None:
        execution = stored.entity
        record_audit_event(
            self._session,
            execution.engagement_id,
            event_type,
            _JANITOR_ACTOR,
            {
                "worker_id": execution.id,
                "request_id": execution.request_id,
                "runtime_identity": self._runtime.identity,
                "worker_state": execution.state.value,
                "reason": reason,
            },
            at=at,
        )

    def _aware_now(self) -> datetime:
        value = self._clock()
        if value.tzinfo is None or value.utcoffset() is None:
            raise RuntimeJanitorError("janitor_clock_must_be_timezone_aware")
        return value

    @staticmethod
    def _outcome(
        resource: RuntimeResource,
        status: JanitorStatus,
        reason: str,
    ) -> JanitorOutcome:
        return JanitorOutcome(
            worker_id=str(resource.worker_id),
            request_id=resource.request_id,
            status=status,
            reason=reason,
        )


async def recover_runtime_after_restart(
    session: Session,
    manager: WorkerManager,
    runtime: WorkerRuntime,
    *,
    at: datetime | None = None,
    grace_period: timedelta = timedelta(minutes=5),
) -> RuntimeRecovery:
    """Fail closed in-flight registry rows, then remove their runtime resources."""
    timestamp = at or _utc_now()
    if timestamp.tzinfo is None or timestamp.utcoffset() is None:
        raise RuntimeJanitorError("janitor_clock_must_be_timezone_aware")
    reconciled = ActionWorkerCoordinator(session, manager).reconcile_after_restart(
        at=timestamp
    )
    sweep = await OrphanRuntimeJanitor(
        session,
        runtime,
        grace_period=grace_period,
        clock=lambda: timestamp,
    ).sweep()
    return RuntimeRecovery(reconciled=reconciled, sweep=sweep)
