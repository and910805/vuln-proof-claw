"""Tests for exact-binding approval consumption and replay prevention."""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import replace
from datetime import UTC, datetime, timedelta

import pytest

from vuln_proof_claw.domain.enums import RiskLevel
from vuln_proof_claw.domain.errors import InvalidApprovalError
from vuln_proof_claw.domain.identifiers import new_engagement_id, new_task_id
from vuln_proof_claw.domain.models import Action, Approval
from vuln_proof_claw.policy.approval import consume_approval, validate_approval

NOW = datetime(2026, 7, 30, 12, 0, tzinfo=UTC)


def make_action() -> Action:
    return Action(
        engagement_id=new_engagement_id(),
        task_id=new_task_id(),
        action_type="file_upload",
        normalized_target="https://example.com:443/api/upload",
        parameter_digest="a" * 64,
        risk_level=RiskLevel.L2,
        idempotency_key="upload-1",
        created_at=NOW,
    )


def make_approval(action: Action, *, permitted_executions: int = 1) -> Approval:
    return Approval(
        engagement_id=action.engagement_id,
        action_type=action.action_type,
        normalized_target=action.normalized_target,
        parameter_digest=action.parameter_digest,
        risk_level=action.risk_level,
        expires_at=NOW + timedelta(minutes=10),
        permitted_executions=permitted_executions,
        approver="security-lead@example.test",
        approved_at=NOW,
    )


def test_consumption_returns_new_immutable_approval() -> None:
    action = make_action()
    approval = make_approval(action, permitted_executions=2)

    consumed = consume_approval(approval, action, at=NOW + timedelta(seconds=1))

    assert approval.consumed_executions == 0
    assert consumed.consumed_executions == 1
    validate_approval(consumed, action, at=NOW + timedelta(seconds=2))


def test_single_use_approval_rejects_replay() -> None:
    action = make_action()
    approval = make_approval(action)
    consumed = consume_approval(approval, action, at=NOW + timedelta(seconds=1))

    with pytest.raises(InvalidApprovalError):
        consume_approval(consumed, action, at=NOW + timedelta(seconds=2))


@pytest.mark.parametrize(
    "changed_action",
    [
        lambda action: replace(action, normalized_target="https://example.com:443/api/admin"),
        lambda action: replace(action, parameter_digest="b" * 64),
        lambda action: replace(action, action_type="password_test"),
        lambda action: replace(action, risk_level=RiskLevel.L3),
        lambda action: replace(action, engagement_id=new_engagement_id()),
    ],
)
def test_protected_property_changes_invalidate_approval(
    changed_action: Callable[[Action], Action],
) -> None:
    action = make_action()
    approval = make_approval(action)

    with pytest.raises(InvalidApprovalError):
        validate_approval(approval, changed_action(action), at=NOW)
