"""Tests for deterministic risk classification and policy decisions."""

from __future__ import annotations

from dataclasses import replace
from datetime import UTC, datetime, timedelta

import pytest

from vuln_proof_claw.domain.enums import RiskLevel
from vuln_proof_claw.domain.identifiers import new_engagement_id, new_task_id
from vuln_proof_claw.domain.models import Action, Approval
from vuln_proof_claw.policy.decision import (
    DecisionKind,
    PolicyConfig,
    decide_action,
)
from vuln_proof_claw.policy.risk import (
    classify_risk,
    is_permanently_denied,
    normalize_action_type,
)
from vuln_proof_claw.policy.scope import EngagementScope

NOW = datetime(2026, 7, 30, 12, 0, tzinfo=UTC)
DIGEST = "a" * 64
TARGET = "https://example.com:443/api"


def make_action(action_type: str, risk_level: RiskLevel) -> Action:
    return Action(
        engagement_id=new_engagement_id(),
        task_id=new_task_id(),
        action_type=action_type,
        normalized_target=TARGET,
        parameter_digest=DIGEST,
        risk_level=risk_level,
        idempotency_key=f"{action_type}-1",
        created_at=NOW,
    )


def make_scope() -> EngagementScope:
    return EngagementScope.create(
        allowed_hostnames=("example.com",),
        allowed_ports=(443,),
        allowed_paths=("/api",),
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


@pytest.mark.parametrize(
    ("action_type", "expected"),
    [
        ("Public Page Read", RiskLevel.L0),
        ("directory-enumeration", RiskLevel.L1),
        ("file_upload", RiskLevel.L2),
        ("privilege_escalation", RiskLevel.L3),
        ("data_deletion", RiskLevel.L4),
        ("new_unknown_capability", RiskLevel.L2),
    ],
)
def test_classification_is_deterministic_and_unknown_is_conservative(
    action_type: str,
    expected: RiskLevel,
) -> None:
    assert classify_risk(action_type) is expected


def test_permanent_deny_action_types_are_separate_from_risk() -> None:
    assert is_permanently_denied("disable-security-controls")
    assert not is_permanently_denied("public_page_read")
    assert normalize_action_type(" Active API Probe ") == "active_api_probe"


def test_l0_is_automatic_and_l1_is_project_configurable() -> None:
    scope = make_scope()
    l0 = make_action("public_page_read", RiskLevel.L0)
    l1 = make_action("active_api_probe", RiskLevel.L1)

    l0_decision = decide_action(
        l0,
        scope=scope,
        config=PolicyConfig(maximum_risk=RiskLevel.L3),
        at=NOW,
    )
    l1_pending = decide_action(
        l1,
        scope=scope,
        config=PolicyConfig(maximum_risk=RiskLevel.L3),
        at=NOW,
    )
    l1_auto = decide_action(
        l1,
        scope=scope,
        config=PolicyConfig(maximum_risk=RiskLevel.L3, auto_execute_l1=True),
        at=NOW,
    )

    assert l0_decision.kind is DecisionKind.ALLOW
    assert l1_pending.kind is DecisionKind.APPROVAL_REQUIRED
    assert l1_auto.kind is DecisionKind.ALLOW


def test_l2_requires_an_exact_valid_approval() -> None:
    action = make_action("file_upload", RiskLevel.L2)
    approval = make_approval(action)

    pending = decide_action(
        action,
        scope=make_scope(),
        config=PolicyConfig(maximum_risk=RiskLevel.L3),
        at=NOW,
    )
    allowed = decide_action(
        action,
        scope=make_scope(),
        config=PolicyConfig(maximum_risk=RiskLevel.L3),
        at=NOW,
        approval=approval,
    )
    changed = decide_action(
        replace(action, parameter_digest="b" * 64),
        scope=make_scope(),
        config=PolicyConfig(maximum_risk=RiskLevel.L3),
        at=NOW,
        approval=approval,
    )

    assert pending.kind is DecisionKind.APPROVAL_REQUIRED
    assert allowed.kind is DecisionKind.ALLOW
    assert allowed.approval_id == approval.id
    assert changed.reason == "approval_invalid"


def test_l4_requires_enablement_and_per_action_approval() -> None:
    action = make_action("data_deletion", RiskLevel.L4)
    approval = make_approval(action)

    disabled = decide_action(
        action,
        scope=make_scope(),
        config=PolicyConfig(maximum_risk=RiskLevel.L4),
        at=NOW,
        approval=approval,
    )
    enabled = decide_action(
        action,
        scope=make_scope(),
        config=PolicyConfig(
            maximum_risk=RiskLevel.L4,
            destructive_actions_enabled=True,
        ),
        at=NOW,
        approval=approval,
    )

    assert disabled.reason == "destructive_actions_disabled"
    assert enabled.kind is DecisionKind.ALLOW


def test_policy_rejects_risk_spoofing_permanent_denies_and_out_of_scope() -> None:
    spoofed = make_action("file_upload", RiskLevel.L0)
    permanently_denied = make_action("cover_tracks", RiskLevel.L2)
    out_of_scope = replace(
        make_action("public_page_read", RiskLevel.L0),
        normalized_target="https://outside.example:443/api",
    )
    config = PolicyConfig(maximum_risk=RiskLevel.L4, destructive_actions_enabled=True)

    assert decide_action(spoofed, scope=make_scope(), config=config, at=NOW).reason == (
        "risk_classification_mismatch"
    )
    assert decide_action(
        permanently_denied,
        scope=make_scope(),
        config=config,
        at=NOW,
    ).reason == "system_permanent_deny"
    assert decide_action(out_of_scope, scope=make_scope(), config=config, at=NOW).reason == (
        "host_not_allowed"
    )


def test_policy_requires_canonical_target_string() -> None:
    action = replace(
        make_action("public_page_read", RiskLevel.L0),
        normalized_target="https://EXAMPLE.com/api",
    )

    decision = decide_action(
        action,
        scope=make_scope(),
        config=PolicyConfig(maximum_risk=RiskLevel.L0),
        at=NOW,
    )

    assert decision.reason == "target_not_normalized"
