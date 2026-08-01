"""Bind disposable Worker outcomes to durable Action and audit state."""

from __future__ import annotations

from dataclasses import replace
from datetime import UTC, datetime

from sqlalchemy.orm import Session

from vuln_proof_claw.audit import record_audit_event
from vuln_proof_claw.domain.action_state import transition_action
from vuln_proof_claw.domain.enums import ActionState, WorkerState
from vuln_proof_claw.domain.identifiers import EngagementId, WorkerId
from vuln_proof_claw.domain.models import Action, WorkerExecution
from vuln_proof_claw.execution.authorization import (
    ExecutionAuthorizationError,
    authorize_queued_action,
    begin_execution,
)
from vuln_proof_claw.execution.manager import (
    WorkerHandle,
    WorkerManager,
    WorkerManagerError,
)
from vuln_proof_claw.execution.protocol import (
    WorkerRequest,
    WorkerResponse,
    WorkerResultStatus,
    WorkerScope,
)
from vuln_proof_claw.persistence.repositories import (
    ActionRepository,
    EvidenceRepository,
    ScopeRepository,
    Stored,
    WorkerExecutionRepository,
)
from vuln_proof_claw.policy.scope import EngagementScope

_SYSTEM_ACTOR = "system:worker-manager"


class WorkerLifecycleError(Exception):
    """Safe failure raised by the durable Worker orchestration boundary."""


class ActionWorkerCoordinator:
    """Start one authorized disposable Worker and persist its terminal outcome."""

    def __init__(self, session: Session, manager: WorkerManager) -> None:
        self._session = session
        self._manager = manager

    async def start(
        self,
        request: WorkerRequest,
        *,
        actor: str,
        at: datetime | None = None,
    ) -> WorkerHandle:
        """Create stopped, consume authority, then start the disposable Worker."""
        timestamp = at or datetime.now(UTC)
        stored_action = ActionRepository(self._session).get(request.action_id)
        if stored_action is None:
            raise WorkerLifecycleError("action_not_found")
        self._verify_request(request, stored_action.entity)
        try:
            authorization = authorize_queued_action(
                self._session,
                stored_action,
                at=timestamp,
            )
        except ExecutionAuthorizationError as error:
            raise WorkerLifecycleError(str(error)) from error

        execution_repository = WorkerExecutionRepository(self._session)
        if execution_repository.get_for_action(request.action_id) is not None:
            raise WorkerLifecycleError("worker_execution_already_registered")
        if execution_repository.get_for_request(request.request_id) is not None:
            raise WorkerLifecycleError("worker_request_already_registered")

        handle = await self._manager.submit(request)
        try:
            stored_execution = execution_repository.add(
                WorkerExecution(
                    id=handle.worker_id,
                    request_id=request.request_id,
                    engagement_id=request.engagement_id,
                    action_id=request.action_id,
                    runtime_identity=self._manager.runtime_identity,
                    state=handle.state,
                    cleaned_up=handle.cleaned_up,
                    error_code=handle.error_code,
                    created_at=handle.created_at,
                    updated_at=handle.updated_at or timestamp,
                )
            )
        except Exception:
            await self._manager.cancel(handle.worker_id)
            raise
        self._audit(
            request.engagement_id,
            "worker.created",
            actor,
            {"worker_id": handle.worker_id, "runtime_identity": self._manager.runtime_identity},
            at=timestamp,
        )
        try:
            running = begin_execution(self._session, authorization, at=timestamp)
        except Exception:
            cancelled = await self._manager.cancel(handle.worker_id)
            self._save_execution(stored_execution, cancelled, at=timestamp)
            self._audit_destroyed(request.engagement_id, cancelled, at=timestamp)
            raise

        try:
            started = await self._manager.start(handle.worker_id)
        except WorkerManagerError as error:
            terminal = await self._manager.status(handle.worker_id)
            lost = transition_action(running.entity, ActionState.WORKER_LOST, at=timestamp)
            ActionRepository(self._session).save(lost, expected_version=running.version)
            self._audit(
                request.engagement_id,
                "worker.start_failed",
                _SYSTEM_ACTOR,
                {
                    "worker_id": handle.worker_id,
                    "error_code": str(error),
                },
                at=timestamp,
            )
            if terminal is not None:
                self._save_execution(stored_execution, terminal, at=timestamp)
                self._audit_destroyed(request.engagement_id, terminal, at=timestamp)
                return terminal
            raise WorkerLifecycleError(str(error)) from error

        self._save_execution(stored_execution, started, at=timestamp)
        self._audit(
            request.engagement_id,
            "worker.started",
            _SYSTEM_ACTOR,
            {"worker_id": handle.worker_id},
            at=timestamp,
        )
        return started

    async def collect(
        self,
        worker_id: str,
        *,
        at: datetime | None = None,
    ) -> WorkerResponse:
        """Collect one response, verify its evidence, and close the Action."""
        timestamp = at or datetime.now(UTC)
        stored_execution = WorkerExecutionRepository(self._session).get(WorkerId(worker_id))
        if stored_execution is None:
            raise WorkerLifecycleError("worker_action_binding_not_found")
        response = await self._manager.collect(worker_id)
        handle = await self._manager.status(worker_id)
        if response is None or handle is None:
            raise WorkerLifecycleError("worker_terminal_response_missing")
        self._save_execution(stored_execution, handle, at=timestamp)
        stored_action = ActionRepository(self._session).get(stored_execution.entity.action_id)
        if stored_action is None or stored_action.entity.state is not ActionState.RUNNING:
            raise WorkerLifecycleError("action_not_running")

        reported_status = response.status
        target = self._terminal_action_state(response, handle)
        error_code = response.error_code
        if target is ActionState.SUCCEEDED and not self._evidence_belongs_to_action(response):
            target = ActionState.FAILED
            error_code = "worker_evidence_binding_invalid"
            response = WorkerResponse(
                request_id=response.request_id,
                engagement_id=response.engagement_id,
                action_id=response.action_id,
                status=WorkerResultStatus.FAILED,
                started_at=response.started_at,
                completed_at=response.completed_at,
                exit_code=response.exit_code,
                error_code=error_code,
            )
        terminal = transition_action(stored_action.entity, target, at=timestamp)
        ActionRepository(self._session).save(terminal, expected_version=stored_action.version)
        self._audit(
            response.engagement_id,
            "worker.collected",
            _SYSTEM_ACTOR,
            {
                "worker_id": worker_id,
                "reported_worker_status": reported_status.value,
                "accepted_worker_status": response.status.value,
                "action_state": target.value,
                "error_code": error_code,
                "evidence_ids": [str(value) for value in response.evidence_ids],
            },
            at=timestamp,
        )
        self._audit_destroyed(response.engagement_id, handle, at=timestamp)
        return response

    async def cancel(
        self,
        worker_id: str,
        *,
        actor: str,
        at: datetime | None = None,
    ) -> WorkerHandle:
        """Cancel and destroy a bound Worker, then close its Action."""
        timestamp = at or datetime.now(UTC)
        stored_execution = WorkerExecutionRepository(self._session).get(WorkerId(worker_id))
        if stored_execution is None:
            raise WorkerLifecycleError("worker_action_binding_not_found")
        stored_action = ActionRepository(self._session).get(stored_execution.entity.action_id)
        if stored_action is None or stored_action.entity.state is not ActionState.RUNNING:
            raise WorkerLifecycleError("action_not_running")
        handle = await self._manager.cancel(worker_id)
        self._save_execution(stored_execution, handle, at=timestamp)
        target = (
            ActionState.WORKER_LOST
            if handle.state is WorkerState.LOST
            else ActionState.CANCELLED
        )
        terminal = transition_action(stored_action.entity, target, at=timestamp)
        ActionRepository(self._session).save(terminal, expected_version=stored_action.version)
        self._audit(
            stored_action.entity.engagement_id,
            "worker.cancelled",
            actor,
            {"worker_id": worker_id, "action_state": target.value},
            at=timestamp,
        )
        self._audit_destroyed(stored_action.entity.engagement_id, handle, at=timestamp)
        return handle

    def reconcile_after_restart(
        self,
        *,
        at: datetime | None = None,
    ) -> tuple[WorkerExecution, ...]:
        """Fail closed every in-flight registry row that this process cannot reattach."""
        timestamp = at or datetime.now(UTC)
        execution_repository = WorkerExecutionRepository(self._session)
        action_repository = ActionRepository(self._session)
        reconciled: list[WorkerExecution] = []
        for stored_execution in execution_repository.list_in_flight():
            previous_state = stored_execution.entity.state
            stored_action = action_repository.get(stored_execution.entity.action_id)
            timestamp_floor = [timestamp, stored_execution.entity.created_at]
            if stored_action is not None:
                timestamp_floor.append(stored_action.entity.created_at)
                if stored_action.entity.started_at is not None:
                    timestamp_floor.append(stored_action.entity.started_at)
            reconciliation_timestamp = max(timestamp_floor)
            lost = replace(
                stored_execution.entity,
                state=WorkerState.LOST,
                cleaned_up=False,
                error_code="worker_recovery_unavailable",
                updated_at=reconciliation_timestamp,
            )
            saved = execution_repository.save(
                lost,
                expected_version=stored_execution.version,
            )
            action_state = "missing"
            if stored_action is not None:
                action_state = stored_action.entity.state.value
                if stored_action.entity.state in {ActionState.QUEUED, ActionState.RUNNING}:
                    terminal = transition_action(
                        stored_action.entity,
                        ActionState.WORKER_LOST,
                        at=reconciliation_timestamp,
                    )
                    action_repository.save(
                        terminal,
                        expected_version=stored_action.version,
                    )
                    action_state = terminal.state.value
            self._audit(
                lost.engagement_id,
                "worker.reconciled_lost",
                "system:startup-recovery",
                {
                    "worker_id": lost.id,
                    "previous_worker_state": previous_state.value,
                    "action_state": action_state,
                    "error_code": lost.error_code,
                },
                at=reconciliation_timestamp,
            )
            reconciled.append(saved.entity)
        return tuple(reconciled)

    def _verify_request(self, request: WorkerRequest, action: Action) -> None:
        bindings = (
            request.engagement_id == action.engagement_id,
            request.action_id == action.id,
            request.action_type == action.action_type,
            request.normalized_target == action.normalized_target,
            request.parameter_digest == action.parameter_digest,
            request.risk_level is action.risk_level,
            request.approval_id == action.approval_id,
            request.idempotency_key == action.idempotency_key,
        )
        if not all(bindings):
            raise WorkerLifecycleError("worker_request_action_binding_mismatch")
        scope = self._scope_for_action(action.engagement_id)
        if request.scope != _worker_scope(scope):
            raise WorkerLifecycleError("worker_request_scope_binding_mismatch")

    def _scope_for_action(self, engagement_id: EngagementId) -> EngagementScope:
        scope = ScopeRepository(self._session).get(engagement_id)
        if scope is None:
            raise WorkerLifecycleError("scope_not_found")
        return scope

    def _evidence_belongs_to_action(self, response: WorkerResponse) -> bool:
        repository = EvidenceRepository(self._session)
        return all(
            (evidence := repository.get(evidence_id)) is not None
            and evidence.action_id == response.action_id
            for evidence_id in response.evidence_ids
        )

    def _save_execution(
        self,
        stored_execution: Stored[WorkerExecution],
        handle: WorkerHandle,
        *,
        at: datetime,
    ) -> Stored[WorkerExecution]:
        if (
            handle.worker_id != stored_execution.entity.id
            or handle.request_id != stored_execution.entity.request_id
        ):
            raise WorkerLifecycleError("worker_handle_registry_binding_mismatch")
        updated = replace(
            stored_execution.entity,
            state=handle.state,
            cleaned_up=handle.cleaned_up,
            error_code=handle.error_code,
            updated_at=handle.updated_at or at,
        )
        return WorkerExecutionRepository(self._session).save(
            updated,
            expected_version=stored_execution.version,
        )

    @staticmethod
    def _terminal_action_state(
        response: WorkerResponse,
        handle: WorkerHandle,
    ) -> ActionState:
        if handle.state is WorkerState.LOST:
            return ActionState.WORKER_LOST
        return {
            WorkerResultStatus.SUCCEEDED: ActionState.SUCCEEDED,
            WorkerResultStatus.FAILED: ActionState.FAILED,
            WorkerResultStatus.TIMED_OUT: ActionState.TIMED_OUT,
            WorkerResultStatus.CANCELLED: ActionState.CANCELLED,
            WorkerResultStatus.POLICY_DENIED: ActionState.FAILED,
            WorkerResultStatus.WORKER_ERROR: ActionState.WORKER_LOST,
        }[response.status]

    def _audit(
        self,
        engagement_id: EngagementId,
        event_type: str,
        actor: str,
        payload: dict[str, object],
        *,
        at: datetime,
    ) -> None:
        record_audit_event(
            self._session,
            engagement_id,
            event_type,
            actor,
            payload,
            at=at,
        )

    def _audit_destroyed(
        self,
        engagement_id: EngagementId,
        handle: WorkerHandle,
        *,
        at: datetime,
    ) -> None:
        self._audit(
            engagement_id,
            "worker.destroyed",
            _SYSTEM_ACTOR,
            {
                "worker_id": handle.worker_id,
                "worker_state": handle.state.value,
                "cleaned_up": handle.cleaned_up,
                "error_code": handle.error_code,
            },
            at=at,
        )


def _worker_scope(scope: EngagementScope) -> WorkerScope:
    return WorkerScope(
        allowed_hostnames=tuple(scope.allowed_hostnames),
        allowed_cidrs=tuple(str(value) for value in scope.allowed_networks),
        allowed_ports=tuple(scope.allowed_ports),
        allowed_schemes=tuple(scope.allowed_schemes),
        allowed_paths=scope.allowed_paths,
        denied_hostnames=tuple(scope.denied_hostnames),
        denied_cidrs=tuple(str(value) for value in scope.denied_networks),
        denied_paths=scope.denied_paths,
    )
