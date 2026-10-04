"""Action executors used by the mission controller.

The controller hands an executor only actions that already carry an ``ALLOW`` policy
decision. An executor must not widen the target, retry on its own, or reinterpret the
plan: it performs exactly the authorized operation and reports what happened.
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, datetime

from sqlalchemy.orm import Session

from vuln_proof_claw.agent.controller import ExecutionResult
from vuln_proof_claw.domain.autonomous import Observation
from vuln_proof_claw.domain.enums import ActionState, ObservationKind
from vuln_proof_claw.domain.identifiers import EngagementId
from vuln_proof_claw.domain.models import Action
from vuln_proof_claw.execution.http_capture import (
    HttpCaptureCoordinator,
    HttpCaptureError,
    HttpCaptureLimits,
    HttpCaptureRequest,
    HttpCaptureResult,
    HttpCaptureTransport,
)
from vuln_proof_claw.persistence.autonomous_repositories import ObservationRepository
from vuln_proof_claw.policy.decision import PolicyDecision
from vuln_proof_claw.policy.scope import normalize_target

_SUPPORTED_ACTION_TYPES = frozenset({"public_page_read"})


def _utc_now() -> datetime:
    return datetime.now(UTC)


@dataclass(frozen=True, slots=True)
class RefusingExecutor:
    """An executor that performs nothing.

    This is the safe default for a controller that has no execution backend wired, and
    the one used when planning or dry-running a mission.
    """

    reason: str = "no_execution_backend"

    def execute(self, action: Action, *, decision: PolicyDecision) -> ExecutionResult:
        return ExecutionResult(succeeded=False, reason=self.reason)


class HttpCaptureExecutor:
    """Perform an authorized passive read through the scope-enforcing capture path.

    Evidence is written by :class:`HttpCaptureCoordinator`, which re-authorizes the
    action against the live database scope before any traffic is sent. A successful
    capture is additionally recorded as an observation so that the knowledge base can
    detect future changes to the same target.
    """

    def __init__(
        self,
        session: Session,
        transport: HttpCaptureTransport,
        *,
        engagement_id: EngagementId,
        limits: HttpCaptureLimits | None = None,
        clock: Callable[[], datetime] = _utc_now,
    ) -> None:
        self._session = session
        self._engagement_id = engagement_id
        self._limits = limits or HttpCaptureLimits()
        self._clock = clock
        self._coordinator = HttpCaptureCoordinator(session, transport)
        self._observations = ObservationRepository(session)

    def execute(self, action: Action, *, decision: PolicyDecision) -> ExecutionResult:
        if action.action_type not in _SUPPORTED_ACTION_TYPES:
            return ExecutionResult(succeeded=False, reason="action_type_not_supported")

        request = HttpCaptureRequest(
            action_id=action.id,
            method="GET",
            target=action.normalized_target,
            query=action.query,
        )
        at = self._clock()
        try:
            result = self._coordinator.capture(request, limits=self._limits, at=at)
        except HttpCaptureError as error:
            return ExecutionResult(succeeded=False, reason=str(error) or "capture_failed")

        if result.action_state is not ActionState.SUCCEEDED or result.evidence is None:
            return ExecutionResult(
                succeeded=False,
                reason=result.error_code or "capture_failed",
            )

        self._record_observation(action, result_summary=self._summarize(result), at=at)
        return ExecutionResult(
            succeeded=True,
            reason="capture_recorded",
            evidence_ids=(str(result.evidence.metadata.evidence_id),),
        )

    def _record_observation(self, action: Action, *, result_summary: str, at: datetime) -> None:
        subject = normalize_target(action.normalized_target).host
        self._observations.add(
            Observation(
                engagement_id=self._engagement_id,
                kind=ObservationKind.HTTP_RESPONSE,
                subject=subject,
                digest=action.parameter_digest,
                summary=result_summary,
                observed_at=at,
            )
        )

    @staticmethod
    def _summarize(result: HttpCaptureResult) -> str:
        if result.response is None:  # pragma: no cover - guarded by the caller
            return "status=unknown bytes=0"
        return f"status={result.response.status_code} bytes={len(result.response.body)}"


__all__ = ["HttpCaptureExecutor", "RefusingExecutor"]
