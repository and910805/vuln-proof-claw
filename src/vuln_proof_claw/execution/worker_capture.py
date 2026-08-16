"""Persist worker-captured evidence through the control-plane evidence chain.

This coordinator closes the capture loop: it authorizes a queued Action, runs a
disposable worker to perform the fetch, and commits the worker's returned
response as tamper-evident evidence bound to the engagement before transitioning
the Action. The worker never touches the database; the control plane holds all
authority and owns evidence persistence.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Literal, Protocol, cast

from sqlalchemy.orm import Session

from vuln_proof_claw.audit import record_audit_event
from vuln_proof_claw.config.models import DockerConfig
from vuln_proof_claw.domain.action_state import transition_action
from vuln_proof_claw.domain.enums import ActionState
from vuln_proof_claw.domain.identifiers import (
    ActionId,
    EvidenceId,
    new_evidence_id,
    new_identifier,
)
from vuln_proof_claw.domain.models import Action
from vuln_proof_claw.evidence.canonical import canonical_json
from vuln_proof_claw.evidence.models import EvidenceMetadata
from vuln_proof_claw.evidence.persistence import PersistentEvidenceStore
from vuln_proof_claw.execution.authorization import (
    ExecutionAuthorization,
    ExecutionAuthorizationError,
    authorize_queued_action,
    begin_execution,
)
from vuln_proof_claw.execution.capture_envelope import CaptureEnvelope
from vuln_proof_claw.execution.docker_runtime import (
    DockerWorkerRuntime,
    SubprocessDockerCommandRunner,
)
from vuln_proof_claw.execution.protocol import (
    WorkerLimits,
    WorkerRequest,
    WorkerScope,
)
from vuln_proof_claw.persistence.repositories import (
    ActionRepository,
    ScopeRepository,
    Stored,
)
from vuln_proof_claw.policy.scope import EngagementScope

_SYSTEM_ACTOR = "system:worker-capture"
_EVIDENCE_MEDIA_TYPE = "application/vnd.vuln-proof-claw.http-capture+json"


class WorkerCaptureError(Exception):
    """Safe, stable failure raised by the worker-capture boundary."""


@dataclass(frozen=True, slots=True)
class CaptureOutcome:
    """Result of one worker capture with the persisted evidence reference."""

    action_state: ActionState
    evidence_id: EvidenceId | None = None
    error_code: str | None = None


class WorkerCaptureRunner(Protocol):
    """Runs one authorized request in a disposable worker and returns its envelope."""

    @property
    def identity(self) -> str:
        """Return the immutable worker runtime/image identity for evidence metadata."""

    async def run(self, request: WorkerRequest) -> CaptureEnvelope:
        """Execute the worker and return its parsed capture envelope."""


def parse_capture_envelope(stdout: str) -> CaptureEnvelope:
    """Return the last line of worker stdout that parses as a capture envelope."""
    for line in reversed(stdout.splitlines()):
        candidate = line.strip()
        if not candidate:
            continue
        try:
            return CaptureEnvelope.model_validate_json(candidate)
        except ValueError:
            continue
    raise WorkerCaptureError("worker_capture_envelope_missing")


class DockerWorkerCaptureRunner:
    """Drive the hardened Docker worker runtime and return its capture envelope."""

    def __init__(self, config: DockerConfig) -> None:
        self._runner = SubprocessDockerCommandRunner(config.cli_path)
        self._runtime = DockerWorkerRuntime(config, self._runner)

    @property
    def identity(self) -> str:
        return self._runtime.identity

    async def run(self, request: WorkerRequest) -> CaptureEnvelope:
        reference = await self._runtime.create(request)
        try:
            await self._runtime.start(reference)
            await self._runner.run(["wait", reference])
            logs = await self._runner.run(["logs", reference])
            return parse_capture_envelope(logs.stdout)
        finally:
            await self._runtime.destroy(reference)


class WorkerCaptureCoordinator:
    """Authorize, run a disposable worker, and persist its evidence in one transaction."""

    def __init__(self, session: Session, runner: WorkerCaptureRunner) -> None:
        self._session = session
        self._runner = runner

    async def capture(
        self,
        action_id: ActionId,
        *,
        actor: str = _SYSTEM_ACTOR,
        at: datetime | None = None,
    ) -> CaptureOutcome:
        timestamp = (at or datetime.now(UTC)).astimezone(UTC)
        action_repository = ActionRepository(self._session)
        stored_action = action_repository.get(action_id)
        if stored_action is None:
            raise WorkerCaptureError("action_not_found")

        try:
            authorization = authorize_queued_action(self._session, stored_action, at=timestamp)
        except ExecutionAuthorizationError as error:
            raise WorkerCaptureError(str(error)) from error

        worker_request = self._build_request(stored_action.entity)
        running = begin_execution(self._session, authorization, at=timestamp)

        try:
            envelope = await self._runner.run(worker_request)
        except Exception as error:  # noqa: BLE001 - untrusted runtime failures become a safe code
            return self._fail(running, "worker_runtime_failure", at=timestamp, cause=error)

        if envelope.status != "succeeded":
            return self._fail(
                running,
                envelope.error_code or "worker_capture_failed",
                at=timestamp,
            )
        return self._succeed(running, authorization, envelope, at=timestamp)

    def _succeed(
        self,
        running: Stored[Action],
        authorization: ExecutionAuthorization,
        envelope: CaptureEnvelope,
        *,
        at: datetime,
    ) -> CaptureOutcome:
        action = running.entity
        evidence_id = new_evidence_id()
        metadata = EvidenceMetadata(
            evidence_id=evidence_id,
            engagement_id=action.engagement_id,
            action_id=action.id,
            tool_name="http-capture",
            tool_version="v1",
            normalized_parameters={
                "headers": [],
                "method": "GET",
                "target": action.normalized_target,
            },
            captured_at=at,
            duration_ms=envelope.duration_ms or 0,
            worker_image=self._runner.identity,
            environment={"redirects": "disabled", "transport": "docker-worker"},
            scope_decision=authorization.decision.reason,
            approval_id=action.approval_id,
            media_type=_EVIDENCE_MEDIA_TYPE,
        )
        PersistentEvidenceStore(self._session).append(metadata, _evidence_bytes(action, envelope))
        succeeded = transition_action(action, ActionState.SUCCEEDED, at=at)
        ActionRepository(self._session).save(succeeded, expected_version=running.version)
        self._audit(
            action,
            "worker_capture.succeeded",
            {"evidence_id": evidence_id, "status_code": envelope.status_code},
            at=at,
        )
        return CaptureOutcome(ActionState.SUCCEEDED, evidence_id=evidence_id)

    def _fail(
        self,
        running: Stored[Action],
        error_code: str,
        *,
        at: datetime,
        cause: BaseException | None = None,
    ) -> CaptureOutcome:
        del cause  # untrusted failure detail is intentionally not surfaced
        failed = transition_action(running.entity, ActionState.FAILED, at=at)
        ActionRepository(self._session).save(failed, expected_version=running.version)
        self._audit(running.entity, "worker_capture.failed", {"error_code": error_code}, at=at)
        return CaptureOutcome(ActionState.FAILED, error_code=error_code)

    def _build_request(self, action: Action) -> WorkerRequest:
        scope = ScopeRepository(self._session).get(action.engagement_id)
        if scope is None:
            raise WorkerCaptureError("scope_not_found")
        return WorkerRequest(
            request_id=new_identifier(),
            engagement_id=action.engagement_id,
            action_id=action.id,
            action_type=action.action_type,
            normalized_target=action.normalized_target,
            parameter_digest=action.parameter_digest,
            risk_level=action.risk_level,
            approval_id=action.approval_id,
            idempotency_key=action.idempotency_key,
            capabilities=("http_client",),
            scope=_worker_scope(scope),
            limits=WorkerLimits(
                timeout_seconds=300,
                memory_megabytes=512,
                cpu_count=1.0,
                process_limit=128,
            ),
        )

    def _audit(
        self,
        action: Action,
        event_type: str,
        payload: dict[str, object],
        *,
        at: datetime,
    ) -> None:
        record_audit_event(
            self._session,
            action.engagement_id,
            event_type,
            _SYSTEM_ACTOR,
            {"action_id": action.id, **payload},
            at=at,
        )


def _worker_scope(scope: EngagementScope) -> WorkerScope:
    return WorkerScope(
        allowed_hostnames=tuple(scope.allowed_hostnames),
        allowed_cidrs=tuple(str(value) for value in scope.allowed_networks),
        allowed_ports=tuple(scope.allowed_ports),
        allowed_schemes=cast(
            "tuple[Literal['http', 'https'], ...]", tuple(scope.allowed_schemes)
        ),  # values are re-normalized by WorkerScope
        allowed_paths=scope.allowed_paths,
        denied_hostnames=tuple(scope.denied_hostnames),
        denied_cidrs=tuple(str(value) for value in scope.denied_networks),
        denied_paths=scope.denied_paths,
    )


def _evidence_bytes(action: Action, envelope: CaptureEnvelope) -> bytes:
    return canonical_json(
        {
            "capture_schema": "http-v1",
            "request": {"headers": [], "method": "GET", "target": action.normalized_target},
            "response": {
                "body_base64": envelope.body_base64,
                "body_sha256": envelope.body_sha256,
                "final_target": envelope.final_target,
                "headers": [list(item) for item in envelope.headers],
                "status_code": envelope.status_code,
            },
        }
    )
