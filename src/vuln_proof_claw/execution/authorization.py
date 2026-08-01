"""Shared execution-start authorization and one-shot approval consumption."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime

from sqlalchemy.orm import Session

from vuln_proof_claw.domain.action_state import transition_action
from vuln_proof_claw.domain.enums import ActionState
from vuln_proof_claw.domain.models import Action, Approval
from vuln_proof_claw.persistence.repositories import (
    ActionRepository,
    ApprovalRepository,
    EngagementRepository,
    ScopeRepository,
    Stored,
)
from vuln_proof_claw.policy.approval import consume_approval
from vuln_proof_claw.policy.decision import (
    DecisionKind,
    PolicyConfig,
    PolicyDecision,
    decide_action,
)


class ExecutionAuthorizationError(Exception):
    """Safe, stable refusal raised before a target-facing runtime may start."""


@dataclass(frozen=True, slots=True)
class ExecutionAuthorization:
    action: Stored[Action]
    approval: Stored[Approval] | None
    decision: PolicyDecision


def authorize_queued_action(
    session: Session,
    stored_action: Stored[Action],
    *,
    at: datetime,
) -> ExecutionAuthorization:
    """Recheck persisted authority immediately before execution begins."""
    action = stored_action.entity
    if action.state is not ActionState.QUEUED:
        raise ExecutionAuthorizationError("action_not_queued")
    stored_engagement = EngagementRepository(session).get(action.engagement_id)
    scope = ScopeRepository(session).get(action.engagement_id)
    if stored_engagement is None or scope is None:
        raise ExecutionAuthorizationError("engagement_or_scope_not_found")
    stored_approval = None
    approval = None
    if action.approval_id is not None:
        stored_approval = ApprovalRepository(session).get(action.approval_id)
        if stored_approval is None:
            raise ExecutionAuthorizationError("approval_record_missing")
        approval = stored_approval.entity
    engagement = stored_engagement.entity
    decision = decide_action(
        action,
        scope=scope,
        config=PolicyConfig(
            maximum_risk=engagement.maximum_risk,
            destructive_actions_enabled=engagement.destructive_actions_enabled,
        ),
        at=at,
        approval=approval,
    )
    if decision.kind is not DecisionKind.ALLOW:
        raise ExecutionAuthorizationError(decision.reason)
    return ExecutionAuthorization(stored_action, stored_approval, decision)


def begin_execution(
    session: Session,
    authorization: ExecutionAuthorization,
    *,
    at: datetime,
) -> Stored[Action]:
    """Atomically mark an Action running and consume any bound Approval."""
    running = transition_action(authorization.action.entity, ActionState.RUNNING, at=at)
    saved = ActionRepository(session).save(
        running,
        expected_version=authorization.action.version,
    )
    if authorization.approval is not None:
        consumed = consume_approval(
            authorization.approval.entity,
            authorization.action.entity,
            at=at,
        )
        ApprovalRepository(session).save(
            consumed,
            expected_version=authorization.approval.version,
        )
    return saved
