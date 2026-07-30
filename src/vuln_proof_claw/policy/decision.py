"""Top-level deterministic policy decisions."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from enum import StrEnum

from vuln_proof_claw.domain.enums import RiskLevel
from vuln_proof_claw.domain.errors import InvalidApprovalError
from vuln_proof_claw.domain.models import Action, Approval
from vuln_proof_claw.policy.approval import validate_approval
from vuln_proof_claw.policy.risk import classify_risk, is_permanently_denied
from vuln_proof_claw.policy.scope import EngagementScope, NormalizedTarget, evaluate_scope


class DecisionKind(StrEnum):
    """Possible execution-policy outcomes."""

    ALLOW = "allow"
    APPROVAL_REQUIRED = "approval_required"
    DENY = "deny"


@dataclass(frozen=True, slots=True)
class PolicyConfig:
    """Engagement-specific execution controls."""

    maximum_risk: RiskLevel
    auto_execute_l1: bool = False
    destructive_actions_enabled: bool = False


@dataclass(frozen=True, slots=True)
class PolicyDecision:
    """Auditable result of scope, risk, and approval enforcement."""

    kind: DecisionKind
    reason: str
    risk_level: RiskLevel
    target: NormalizedTarget
    requires_dns_recheck: bool
    approval_id: str | None = None


def _risk_rank(level: RiskLevel) -> int:
    return int(level.value[1])


def decide_action(
    action: Action,
    *,
    scope: EngagementScope,
    config: PolicyConfig,
    at: datetime,
    approval: Approval | None = None,
) -> PolicyDecision:
    """Apply permanent-deny, scope, risk, and approval rules in precedence order."""
    scope_decision = evaluate_scope(action.normalized_target, scope, at=at)
    classified_risk = classify_risk(action.action_type)

    approval_id: str | None = None
    if is_permanently_denied(action.action_type):
        kind, reason = DecisionKind.DENY, "system_permanent_deny"
    elif not scope_decision.allowed:
        kind, reason = DecisionKind.DENY, scope_decision.reason
    elif action.normalized_target != str(scope_decision.target):
        kind, reason = DecisionKind.DENY, "target_not_normalized"
    elif action.risk_level is not classified_risk:
        kind, reason = DecisionKind.DENY, "risk_classification_mismatch"
    elif _risk_rank(classified_risk) > _risk_rank(config.maximum_risk):
        kind, reason = DecisionKind.DENY, "risk_exceeds_engagement_maximum"
    elif classified_risk is RiskLevel.L4 and not config.destructive_actions_enabled:
        kind, reason = DecisionKind.DENY, "destructive_actions_disabled"
    else:
        approval_required = classified_risk.requires_approval or (
            classified_risk is RiskLevel.L1 and not config.auto_execute_l1
        )
        if not approval_required:
            kind, reason = DecisionKind.ALLOW, "automatic_policy_allow"
        elif approval is None:
            kind, reason = DecisionKind.APPROVAL_REQUIRED, "explicit_approval_required"
        else:
            try:
                validate_approval(approval, action, at=at)
            except InvalidApprovalError:
                kind, reason = DecisionKind.APPROVAL_REQUIRED, "approval_invalid"
            else:
                kind, reason = DecisionKind.ALLOW, "valid_approval"
                approval_id = approval.id
    return PolicyDecision(
        kind=kind,
        reason=reason,
        risk_level=classified_risk,
        target=scope_decision.target,
        requires_dns_recheck=scope_decision.requires_dns_recheck,
        approval_id=approval_id,
    )
