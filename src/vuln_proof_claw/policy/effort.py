"""Match reasoning effort and output budget to the risk of the action.

Running every step at the highest effort is measurably wasteful: on the same
targets it cost 1.3 to 1.7 times as much and bought deeper verification of
findings already made, not new findings. Reading a public page does not need
that, and confirming a critical exploit does. The multiplier also moved with the
target, so a single global setting is wrong in both directions.

The output budget matters for a different reason: when a tool call is cut off
mid-generation the caller sees neither content nor a tool call, which is
indistinguishable from the model having nothing to say.
"""

from __future__ import annotations

from dataclasses import dataclass
from types import MappingProxyType
from typing import Final

from vuln_proof_claw.domain.enums import EffortLevel, RiskLevel
from vuln_proof_claw.policy.risk import classify_risk

MINIMUM_OUTPUT_TOKENS: Final = 4_000


@dataclass(frozen=True, slots=True)
class EffortBudget:
    """Reasoning effort and output ceiling for one action."""

    effort: EffortLevel
    max_output_tokens: int

    def __post_init__(self) -> None:
        if self.max_output_tokens < MINIMUM_OUTPUT_TOKENS:
            raise ValueError(
                f"max_output_tokens must be at least {MINIMUM_OUTPUT_TOKENS}; "
                "a smaller ceiling truncates tool calls mid-generation"
            )


RISK_EFFORT: Final = MappingProxyType(
    {
        RiskLevel.L0: EffortBudget(EffortLevel.LOW, 8_000),
        RiskLevel.L1: EffortBudget(EffortLevel.MEDIUM, 16_000),
        RiskLevel.L2: EffortBudget(EffortLevel.HIGH, 24_000),
        RiskLevel.L3: EffortBudget(EffortLevel.HIGH, 32_000),
        RiskLevel.L4: EffortBudget(EffortLevel.XHIGH, 32_000),
    }
)


def budget_for_risk(risk_level: RiskLevel) -> EffortBudget:
    """Return the effort and output ceiling for a risk level."""
    return RISK_EFFORT[risk_level]


def budget_for_action(action_type: str) -> EffortBudget:
    """Return the effort and output ceiling for an action type."""
    return budget_for_risk(classify_risk(action_type))
