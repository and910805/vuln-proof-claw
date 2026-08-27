from vuln_proof_claw.automation.autonomy import (
    AutonomousDecision,
    AutonomyBudget,
    AutonomySnapshot,
    decide_autonomous_step,
)


def test_autonomy_waits_for_independent_approval_before_operating() -> None:
    outcome = decide_autonomous_step(
        AutonomySnapshot(pending_approvals=1, queued_actions=4),
        AutonomyBudget(),
    )
    assert outcome.decision is AutonomousDecision.WAIT_FOR_APPROVAL
    assert outcome.reason == "independent_approval_required"


def test_autonomy_verifies_results_and_stops_at_budget() -> None:
    verify = decide_autonomous_step(
        AutonomySnapshot(unverified_results=2),
        AutonomyBudget(),
    )
    stopped = decide_autonomous_step(
        AutonomySnapshot(steps=5, unverified_results=2),
        AutonomyBudget(maximum_steps=5),
    )
    assert verify.decision is AutonomousDecision.VERIFY
    assert stopped.decision is AutonomousDecision.STOP
    assert stopped.reason == "maximum_steps_reached"
