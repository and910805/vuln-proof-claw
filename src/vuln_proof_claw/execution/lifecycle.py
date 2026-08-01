"""Bind disposable Worker outcomes to durable Action and audit state."""

from __future__ import annotations

from datetime import UTC, datetime

from sqlalchemy.orm import Session

from vuln_proof_claw.audit import record_audit_event
from vuln_proof_claw.domain.action_state import transition_action
from vuln_proof_claw.domain.enums import ActionState
from vuln_proof_claw.domain.identifiers import ActionId, EngagementId
from vuln_proof_claw.domain.models import Action
from vuln_proof_claw.execution.authorization import (
    ExecutionAuthorizationError,
    authorize_queued_action,
    begin_execution,
)
from vuln_proof_claw.execution.manager import (
    WorkerHandle,
    WorkerManager,
    WorkerManagerError,
    WorkerState,
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
        self._worker_actions: dict[str, ActionId] = {}

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

        handle = await self._manager.submit(request)
        self._worker_actions[handle.worker_id] = request.action_id
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
                self._audit_destroyed(request.engagement_id, terminal, at=timestamp)
                return terminal
            raise WorkerLifecycleError(str(error)) from error

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
        action_id = self._worker_actions.get(worker_id)
        if action_id is None:
            raise WorkerLifecycleError("worker_action_binding_not_found")
        response = await self._manager.collect(worker_id)
        handle = await self._manager.status(worker_id)
        if response is None or handle is None:
            raise WorkerLifecycleError("worker_terminal_response_missing")
        stored_action = ActionRepository(self._session).get(action_id)
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
        action_id = self._worker_actions.get(worker_id)
        if action_id is None:
            raise WorkerLifecycleError("worker_action_binding_not_found")
        stored_action = ActionRepository(self._session).get(action_id)
        if stored_action is None or stored_action.entity.state is not ActionState.RUNNING:
            raise WorkerLifecycleError("action_not_running")
        handle = await self._manager.cancel(worker_id)
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
