"""Action lifecycle transition rules."""

from __future__ import annotations

from dataclasses import replace
from datetime import datetime
from types import MappingProxyType
from typing import Final

from vuln_proof_claw.domain.enums import ActionState
from vuln_proof_claw.domain.errors import (
    ApprovalRequiredError,
    InvalidActionTransitionError,
    InvalidApprovalError,
)
from vuln_proof_claw.domain.models import Action, Approval, utc_now

TERMINAL_ACTION_STATES: Final = frozenset(
    {
        ActionState.DENIED,
        ActionState.SUCCEEDED,
        ActionState.FAILED,
        ActionState.TIMED_OUT,
        ActionState.CANCELLED,
        ActionState.WORKER_LOST,
    }
)

ACTION_TRANSITIONS: Final = MappingProxyType(
    {
        ActionState.PROPOSED: frozenset({ActionState.POLICY_CHECK, ActionState.CANCELLED}),
        ActionState.POLICY_CHECK: frozenset(
            {
                ActionState.DENIED,
                ActionState.PENDING_APPROVAL,
                ActionState.QUEUED,
                ActionState.CANCELLED,
            }
        ),
        ActionState.PENDING_APPROVAL: frozenset(
            {ActionState.QUEUED, ActionState.DENIED, ActionState.CANCELLED}
        ),
        ActionState.QUEUED: frozenset({ActionState.RUNNING, ActionState.CANCELLED}),
        ActionState.RUNNING: frozenset(
            {
                ActionState.SUCCEEDED,
                ActionState.FAILED,
                ActionState.TIMED_OUT,
                ActionState.CANCELLED,
                ActionState.WORKER_LOST,
            }
        ),
    }
)


def transition_action(
    action: Action,
    target: ActionState,
    *,
    approval: Approval | None = None,
    at: datetime | None = None,
) -> Action:
    """Return a new action after enforcing its lifecycle invariants."""
    if target not in ACTION_TRANSITIONS.get(action.state, frozenset()):
        raise InvalidActionTransitionError(action.state, target)

    timestamp = at or utc_now()
    requires_approval = (
        target is ActionState.QUEUED
        and (
            action.risk_level.requires_approval
            or action.state is ActionState.PENDING_APPROVAL
        )
    )
    if requires_approval:
        if approval is None:
            raise ApprovalRequiredError
        if not approval.authorizes(action, at=timestamp):
            raise InvalidApprovalError

    return replace(
        action,
        state=target,
        approval_id=approval.id if approval is not None else action.approval_id,
        started_at=timestamp if target is ActionState.RUNNING else action.started_at,
        completed_at=timestamp if target in TERMINAL_ACTION_STATES else action.completed_at,
    )
