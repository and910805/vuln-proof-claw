"""Deterministic guardrails for a Planner/Operator/Verifier agent loop."""

from __future__ import annotations

from enum import StrEnum

from pydantic import BaseModel, ConfigDict, Field


class AutonomousDecision(StrEnum):
    PLAN = "plan"
    OPERATE = "operate"
    WAIT_FOR_APPROVAL = "wait_for_approval"
    VERIFY = "verify"
    COMPLETE = "complete"
    STOP = "stop"


class AutonomyBudget(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    maximum_steps: int = Field(default=50, ge=1, le=500)
    maximum_tool_calls: int = Field(default=100, ge=1, le=1000)
    maximum_duration_seconds: int = Field(default=3600, ge=30, le=86_400)
    maximum_consecutive_failures: int = Field(default=3, ge=1, le=10)


class AutonomySnapshot(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    steps: int = Field(default=0, ge=0)
    tool_calls: int = Field(default=0, ge=0)
    elapsed_seconds: int = Field(default=0, ge=0)
    consecutive_failures: int = Field(default=0, ge=0)
    proposed_actions: int = Field(default=0, ge=0)
    queued_actions: int = Field(default=0, ge=0)
    pending_approvals: int = Field(default=0, ge=0)
    unverified_results: int = Field(default=0, ge=0)


class AutonomyOutcome(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    decision: AutonomousDecision
    reason: str


def decide_autonomous_step(
    snapshot: AutonomySnapshot,
    budget: AutonomyBudget,
) -> AutonomyOutcome:
    """Select the next role without allowing the Agent to approve its own actions."""
    limits = (
        (snapshot.steps >= budget.maximum_steps, "maximum_steps_reached"),
        (snapshot.tool_calls >= budget.maximum_tool_calls, "maximum_tool_calls_reached"),
        (
            snapshot.elapsed_seconds >= budget.maximum_duration_seconds,
            "maximum_duration_reached",
        ),
        (
            snapshot.consecutive_failures >= budget.maximum_consecutive_failures,
            "consecutive_failure_limit_reached",
        ),
    )
    for reached, reason in limits:
        if reached:
            return AutonomyOutcome(decision=AutonomousDecision.STOP, reason=reason)
    if snapshot.pending_approvals:
        return AutonomyOutcome(
            decision=AutonomousDecision.WAIT_FOR_APPROVAL,
            reason="independent_approval_required",
        )
    if snapshot.unverified_results:
        return AutonomyOutcome(
            decision=AutonomousDecision.VERIFY,
            reason="independent_verification_required",
        )
    if snapshot.queued_actions:
        return AutonomyOutcome(decision=AutonomousDecision.OPERATE, reason="queued_action_ready")
    if snapshot.proposed_actions:
        return AutonomyOutcome(decision=AutonomousDecision.PLAN, reason="proposal_requires_policy")
    return AutonomyOutcome(decision=AutonomousDecision.COMPLETE, reason="no_remaining_work")
