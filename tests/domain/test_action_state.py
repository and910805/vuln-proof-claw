"""Tests for the action lifecycle state machine."""

from __future__ import annotations

from dataclasses import replace
from datetime import UTC, datetime, timedelta

import pytest

from vuln_proof_claw.domain.action_state import TERMINAL_ACTION_STATES, transition_action
from vuln_proof_claw.domain.enums import ActionState, RiskLevel
from vuln_proof_claw.domain.errors import (
    ApprovalRequiredError,
    InvalidActionTransitionError,
    InvalidApprovalError,
)
from vuln_proof_claw.domain.identifiers import new_engagement_id, new_task_id
from vuln_proof_claw.domain.models import Action, Approval

NOW = datetime(2026, 7, 30, 12, 0, tzinfo=UTC)
DIGEST = "a" * 64


def make_action(*, risk_level: RiskLevel = RiskLevel.L0) -> Action:
    return Action(
        engagement_id=new_engagement_id(),
        task_id=new_task_id(),
        action_type="http_request",
        normalized_target="https://example.test/health",
        parameter_digest=DIGEST,
        risk_level=risk_level,
        idempotency_key="idempotency-1",
        created_at=NOW,
    )


def make_approval(action: Action) -> Approval:
    return Approval(
        engagement_id=action.engagement_id,
        action_type=action.action_type,
        normalized_target=action.normalized_target,
        parameter_digest=action.parameter_digest,
        risk_level=action.risk_level,
        expires_at=NOW + timedelta(hours=1),
        permitted_executions=1,
        approver="security-lead@example.test",
        approved_at=NOW,
    )


def test_low_risk_action_can_complete_valid_path() -> None:
    action = make_action()

    action = transition_action(action, ActionState.POLICY_CHECK, at=NOW)
    action = transition_action(action, ActionState.QUEUED, at=NOW)
    action = transition_action(action, ActionState.RUNNING, at=NOW)
    action = transition_action(action, ActionState.SUCCEEDED, at=NOW + timedelta(seconds=1))

    assert action.state is ActionState.SUCCEEDED
    assert action.started_at == NOW
    assert action.completed_at == NOW + timedelta(seconds=1)


@pytest.mark.parametrize("risk_level", [RiskLevel.L2, RiskLevel.L3, RiskLevel.L4])
def test_high_risk_actions_require_approval(risk_level: RiskLevel) -> None:
    action = transition_action(make_action(risk_level=risk_level), ActionState.POLICY_CHECK)

    with pytest.raises(ApprovalRequiredError):
        transition_action(action, ActionState.QUEUED, at=NOW + timedelta(minutes=1))


def test_valid_approval_is_bound_when_action_is_queued() -> None:
    action = make_action(risk_level=RiskLevel.L2)
    approval = make_approval(action)
    action = transition_action(action, ActionState.POLICY_CHECK, at=NOW)
    action = transition_action(action, ActionState.PENDING_APPROVAL, at=NOW)

    queued = transition_action(
        action,
        ActionState.QUEUED,
        approval=approval,
        at=NOW + timedelta(minutes=1),
    )

    assert queued.state is ActionState.QUEUED
    assert queued.approval_id == approval.id


def test_parameter_mutation_invalidates_approval() -> None:
    action = make_action(risk_level=RiskLevel.L2)
    approval = make_approval(action)
    changed_action = replace(action, parameter_digest="b" * 64)
    changed_action = transition_action(changed_action, ActionState.POLICY_CHECK, at=NOW)

    with pytest.raises(InvalidApprovalError):
        transition_action(
            changed_action,
            ActionState.QUEUED,
            approval=approval,
            at=NOW + timedelta(minutes=1),
        )


def test_pending_approval_state_requires_approval_even_for_l1() -> None:
    action = make_action(risk_level=RiskLevel.L1)
    action = transition_action(action, ActionState.POLICY_CHECK, at=NOW)
    action = transition_action(action, ActionState.PENDING_APPROVAL, at=NOW)

    with pytest.raises(ApprovalRequiredError):
        transition_action(action, ActionState.QUEUED, at=NOW)


def test_invalid_transition_is_rejected() -> None:
    with pytest.raises(InvalidActionTransitionError):
        transition_action(make_action(), ActionState.RUNNING, at=NOW)


def test_execution_timestamps_cannot_move_backwards() -> None:
    action = make_action()
    action = transition_action(action, ActionState.POLICY_CHECK, at=NOW)
    action = transition_action(action, ActionState.QUEUED, at=NOW)
    action = transition_action(action, ActionState.RUNNING, at=NOW + timedelta(seconds=2))

    with pytest.raises(ValueError, match="started_at"):
        transition_action(action, ActionState.SUCCEEDED, at=NOW + timedelta(seconds=1))


@pytest.mark.parametrize("terminal_state", sorted(TERMINAL_ACTION_STATES))
def test_terminal_states_cannot_transition(terminal_state: ActionState) -> None:
    action = make_action()
    if terminal_state is ActionState.DENIED:
        action = transition_action(action, ActionState.POLICY_CHECK, at=NOW)
        action = transition_action(action, terminal_state, at=NOW)
    elif terminal_state is ActionState.CANCELLED:
        action = transition_action(action, terminal_state, at=NOW)
    else:
        action = transition_action(action, ActionState.POLICY_CHECK, at=NOW)
        action = transition_action(action, ActionState.QUEUED, at=NOW)
        action = transition_action(action, ActionState.RUNNING, at=NOW)
        action = transition_action(action, terminal_state, at=NOW)

    with pytest.raises(InvalidActionTransitionError):
        transition_action(action, ActionState.POLICY_CHECK, at=NOW)
