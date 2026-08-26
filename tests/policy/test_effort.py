"""Tests for matching reasoning effort and output budget to action risk."""

from __future__ import annotations

import pytest

from vuln_proof_claw.domain.enums import EffortLevel, RiskLevel
from vuln_proof_claw.policy.effort import (
    MINIMUM_OUTPUT_TOKENS,
    RISK_EFFORT,
    EffortBudget,
    budget_for_action,
    budget_for_risk,
)


def test_every_risk_level_has_a_budget() -> None:
    assert set(RISK_EFFORT) == set(RiskLevel)


def test_effort_never_decreases_as_risk_rises() -> None:
    order = [EffortLevel.LOW, EffortLevel.MEDIUM, EffortLevel.HIGH, EffortLevel.XHIGH]
    ranks = [order.index(RISK_EFFORT[level].effort) for level in RiskLevel]
    assert ranks == sorted(ranks)


def test_reading_a_public_page_uses_the_cheapest_setting() -> None:
    budget = budget_for_action("public_page_read")
    assert budget.effort is EffortLevel.LOW


def test_confirming_an_exploit_uses_a_high_setting() -> None:
    assert budget_for_action("exploit_attempt").effort is EffortLevel.HIGH


def test_a_scan_sits_in_the_middle() -> None:
    assert budget_for_action("vulnerability_scan").effort is EffortLevel.MEDIUM


def test_unknown_actions_inherit_the_conservative_default() -> None:
    # An unrecognised action is classified L2, so it must not be run cheaply.
    assert budget_for_action("something_new") == budget_for_risk(RiskLevel.L2)


def test_every_output_ceiling_clears_the_truncation_floor() -> None:
    for budget in RISK_EFFORT.values():
        assert budget.max_output_tokens >= MINIMUM_OUTPUT_TOKENS


def test_a_ceiling_below_the_floor_is_refused() -> None:
    with pytest.raises(ValueError, match="truncates tool calls"):
        EffortBudget(EffortLevel.LOW, 16)
