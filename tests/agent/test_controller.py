"""Tests for the persistent mission controller.

These cover the loop's safety properties: that nothing executes without a policy
allow, that the autonomous risk ceiling holds, and that a crash cannot produce
unbounded retries against a target.
"""

from __future__ import annotations

from collections.abc import Generator
from dataclasses import dataclass, field, replace
from datetime import datetime, timedelta
from pathlib import Path

import pytest
from sqlalchemy import Engine
from sqlalchemy.orm import Session

from tests.agent.support import (
    NOW,
    TARGET_HOST,
    TARGET_URL,
    build_engine,
    seed_engagement,
    seed_lead,
    seed_mission,
    seed_surface,
    session_factory,
)
from vuln_proof_claw.agent.controller import (
    DEFAULT_WATCHDOG_SECONDS,
    ExecutionResult,
    MissionController,
    MissionControllerError,
)
from vuln_proof_claw.agent.planner import (
    DeterministicPlanner,
    ProposedAction,
    ResearchPlan,
)
from vuln_proof_claw.domain.autonomous import (
    Lead,
    Mission,
    MissionBudget,
    MissionCadence,
    MissionRun,
)
from vuln_proof_claw.domain.enums import (
    ActionState,
    LeadStatus,
    MissionRunState,
    MissionState,
    RiskLevel,
)
from vuln_proof_claw.domain.identifiers import LeadId, MissionId
from vuln_proof_claw.domain.models import Action
from vuln_proof_claw.persistence.autonomous_repositories import (
    LeadRepository,
    MissionRunRepository,
)
from vuln_proof_claw.persistence.repositories import ActionRepository
from vuln_proof_claw.policy.decision import PolicyDecision

OUT_OF_SCOPE_URL = "https://attacker.test:443/"


@dataclass
class RecordingExecutor:
    """Capture what the controller asked to execute."""

    succeeded: bool = True
    reason: str = "captured"
    executed: list[Action] = field(default_factory=list)
    decisions: list[PolicyDecision] = field(default_factory=list)

    def execute(self, action: Action, *, decision: PolicyDecision) -> ExecutionResult:
        self.executed.append(action)
        self.decisions.append(decision)
        return ExecutionResult(succeeded=self.succeeded, reason=self.reason)


@dataclass
class FixedPlanner:
    """Return a caller-supplied plan regardless of the lead."""

    action_type: str
    target: str
    risk_level: RiskLevel

    def plan(self, lead: Lead, *, mission: Mission) -> ResearchPlan:
        return ResearchPlan(
            lead_id=lead.id,
            objective="probe the target",
            hypothesis=lead.hypothesis,
            proposed_action=ProposedAction(action_type=self.action_type, target=self.target),
            expected_observation="a bounded response",
            reason="test plan",
            success_condition="response differs from baseline",
            failure_condition="response matches baseline",
            risk_level=self.risk_level,
        )


@pytest.fixture
def engine(tmp_path: Path) -> Generator[Engine, None, None]:
    yield from build_engine(tmp_path / "controller.db")


def frozen_clock(moment: datetime = NOW) -> object:
    return lambda: moment


def build_controller(
    session: Session,
    mission_id: MissionId,
    *,
    executor: RecordingExecutor,
    planner: object | None = None,
    now: datetime = NOW,
) -> MissionController:
    return MissionController(
        session,
        mission_id,
        planner=planner or DeterministicPlanner(),  # type: ignore[arg-type]
        executor=executor,
        clock=frozen_clock(now),  # type: ignore[arg-type]
    )


def test_a_cycle_executes_an_in_scope_low_risk_lead(engine: Engine) -> None:
    factory = session_factory(engine)
    executor = RecordingExecutor()
    with factory() as session:
        engagement_id = seed_engagement(session)
        mission = seed_mission(session, engagement_id)
        seed_lead(session, engagement_id, MissionId(mission.id))
        session.commit()

        controller = build_controller(session, MissionId(mission.id), executor=executor)
        run = controller.start_run()
        report = controller.run_cycle(run)

        lead_states = [
            stored.entity.status
            for stored in LeadRepository(session).list_by_status(
                MissionId(mission.id), (LeadStatus.WAITING,)
            )
        ]

    assert len(executor.executed) == 1
    assert executor.executed[0].normalized_target == TARGET_URL
    assert executor.executed[0].state is ActionState.QUEUED
    assert report.outcomes[0].disposition == "executed"
    assert lead_states == [LeadStatus.WAITING]


def test_a_plan_with_a_tampered_risk_level_is_rejected(engine: Engine) -> None:
    factory = session_factory(engine)
    executor = RecordingExecutor()
    with factory() as session:
        engagement_id = seed_engagement(session)
        mission = seed_mission(session, engagement_id)
        lead = seed_lead(session, engagement_id, MissionId(mission.id))
        session.commit()

        # public_page_read is L0; claiming L1 must not be silently corrected.
        controller = build_controller(
            session,
            MissionId(mission.id),
            executor=executor,
            planner=FixedPlanner("public_page_read", TARGET_URL, RiskLevel.L1),
        )
        report = controller.run_cycle(controller.start_run())
        stored = LeadRepository(session).get(LeadId(lead.id))

    assert executor.executed == []
    assert report.outcomes[0].reason == "risk_classification_mismatch"
    assert stored is not None
    assert stored.entity.status is LeadStatus.REJECTED


def test_an_action_above_the_autonomous_ceiling_never_executes(engine: Engine) -> None:
    factory = session_factory(engine)
    executor = RecordingExecutor()
    with factory() as session:
        engagement_id = seed_engagement(session)
        mission = seed_mission(session, engagement_id)
        seed_lead(session, engagement_id, MissionId(mission.id))
        session.commit()

        controller = build_controller(
            session,
            MissionId(mission.id),
            executor=executor,
            planner=FixedPlanner("exploit_attempt", TARGET_URL, RiskLevel.L2),
        )
        report = controller.run_cycle(controller.start_run())

    assert executor.executed == []
    assert report.outcomes[0].reason == "risk_exceeds_autonomous_ceiling"


def test_an_out_of_scope_target_is_denied_by_the_policy_engine(engine: Engine) -> None:
    factory = session_factory(engine)
    executor = RecordingExecutor()
    with factory() as session:
        engagement_id = seed_engagement(session)
        mission = seed_mission(session, engagement_id)
        lead = seed_lead(session, engagement_id, MissionId(mission.id))
        session.commit()

        controller = build_controller(
            session,
            MissionId(mission.id),
            executor=executor,
            planner=FixedPlanner("public_page_read", OUT_OF_SCOPE_URL, RiskLevel.L0),
        )
        report = controller.run_cycle(controller.start_run())
        actions = ActionRepository(session).list_for_engagement(engagement_id)
        stored = LeadRepository(session).get(LeadId(lead.id))

    assert executor.executed == []
    assert report.outcomes[0].disposition == "rejected"
    assert report.outcomes[0].reason == "host_not_allowed"
    assert [item.entity.state for item in actions] == [ActionState.DENIED]
    assert stored is not None
    assert stored.entity.status is LeadStatus.REJECTED


def test_l1_without_auto_execute_requires_approval_instead_of_running(engine: Engine) -> None:
    factory = session_factory(engine)
    executor = RecordingExecutor()
    with factory() as session:
        engagement_id = seed_engagement(session, auto_execute_l1=False)
        mission = seed_mission(session, engagement_id)
        lead = seed_lead(session, engagement_id, MissionId(mission.id))
        session.commit()

        controller = build_controller(
            session,
            MissionId(mission.id),
            executor=executor,
            planner=FixedPlanner("port_scan", TARGET_URL, RiskLevel.L1),
        )
        report = controller.run_cycle(controller.start_run())
        stored = LeadRepository(session).get(LeadId(lead.id))

    assert executor.executed == []
    assert report.outcomes[0].disposition == "needs_approval"
    assert stored is not None
    assert stored.entity.status is LeadStatus.NEEDS_APPROVAL
    assert stored.entity.blocked_reason == "explicit_approval_required"


def test_budget_exhaustion_stops_the_cycle_without_discarding_leads(engine: Engine) -> None:
    factory = session_factory(engine)
    executor = RecordingExecutor()
    with factory() as session:
        engagement_id = seed_engagement(session)
        mission = seed_mission(
            session,
            engagement_id,
            budget=MissionBudget(
                requests_per_minute_per_domain=1,
                maximum_concurrent_actions=5,
            ),
        )
        for index in range(3):
            seed_lead(
                session,
                engagement_id,
                MissionId(mission.id),
                hypothesis=f"hypothesis {index}",
                dedupe_key=f"key-{index}",
            )
        session.commit()

        controller = build_controller(session, MissionId(mission.id), executor=executor)
        report = controller.run_cycle(controller.start_run())

        remaining = LeadRepository(session).list_by_status(
            MissionId(mission.id), (LeadStatus.NEW, LeadStatus.QUEUED)
        )

    assert len(executor.executed) == 1
    assert any(item.reason == "domain_rate_limit_reached" for item in report.outcomes)
    assert len(remaining) >= 1


def test_concurrency_limit_bounds_actions_per_cycle(engine: Engine) -> None:
    factory = session_factory(engine)
    executor = RecordingExecutor()
    with factory() as session:
        engagement_id = seed_engagement(session)
        mission = seed_mission(
            session,
            engagement_id,
            budget=MissionBudget(
                requests_per_minute_per_domain=100,
                maximum_concurrent_actions=2,
            ),
        )
        for index in range(5):
            seed_lead(
                session,
                engagement_id,
                MissionId(mission.id),
                hypothesis=f"hypothesis {index}",
                dedupe_key=f"key-{index}",
            )
        session.commit()

        controller = build_controller(session, MissionId(mission.id), executor=executor)
        controller.run_cycle(controller.start_run())

    assert len(executor.executed) == 2


def test_recovery_marks_stale_runs_and_requeues_investigating_leads(engine: Engine) -> None:
    factory = session_factory(engine)
    executor = RecordingExecutor()
    later = NOW + timedelta(seconds=DEFAULT_WATCHDOG_SECONDS + 60)
    with factory() as session:
        engagement_id = seed_engagement(session)
        mission = seed_mission(session, engagement_id)
        lead = seed_lead(
            session,
            engagement_id,
            MissionId(mission.id),
            status=LeadStatus.INVESTIGATING,
            attempt_count=1,
            last_attempt_at=NOW,
        )
        MissionRunRepository(session).add(
            MissionRun(
                engagement_id=engagement_id,
                mission_id=MissionId(mission.id),
                state=MissionRunState.RUNNING,
                started_at=NOW,
                heartbeat_at=NOW,
            )
        )
        session.commit()

        controller = build_controller(
            session, MissionId(mission.id), executor=executor, now=later
        )
        recovered = controller.recover()
        requeued = LeadRepository(session).get(LeadId(lead.id))
        runs = MissionRunRepository(session).list_running()

    assert len(recovered) == 1
    assert runs == ()
    assert requeued is not None
    assert requeued.entity.status is LeadStatus.QUEUED
    assert requeued.entity.attempt_count == 1


def test_a_healthy_run_is_not_interrupted_by_recovery(engine: Engine) -> None:
    factory = session_factory(engine)
    executor = RecordingExecutor()
    with factory() as session:
        engagement_id = seed_engagement(session)
        mission = seed_mission(session, engagement_id)
        MissionRunRepository(session).add(
            MissionRun(
                engagement_id=engagement_id,
                mission_id=MissionId(mission.id),
                state=MissionRunState.RUNNING,
                started_at=NOW,
                heartbeat_at=NOW,
            )
        )
        session.commit()

        controller = build_controller(
            session, MissionId(mission.id), executor=executor, now=NOW + timedelta(seconds=30)
        )
        recovered = controller.recover()

    assert recovered == ()


@pytest.mark.parametrize(
    ("overrides", "expected"),
    [
        ({"kill_switch_engaged": True}, "kill_switch_engaged"),
        ({"state": MissionState.PAUSED}, "mission_paused"),
        (
            {"created_at": NOW - timedelta(days=2), "expires_at": NOW - timedelta(hours=1)},
            "mission_expired",
        ),
    ],
)
def test_a_mission_that_may_not_run_refuses_to_start(
    engine: Engine,
    overrides: dict[str, object],
    expected: str,
) -> None:
    factory = session_factory(engine)
    executor = RecordingExecutor()
    with factory() as session:
        engagement_id = seed_engagement(session)
        mission = seed_mission(session, engagement_id, **overrides)  # type: ignore[arg-type]
        session.commit()

        controller = build_controller(session, MissionId(mission.id), executor=executor)
        with pytest.raises(MissionControllerError) as error:
            controller.start_run()

    assert str(error.value) == expected


def test_a_failed_execution_applies_a_cooldown_instead_of_retrying(engine: Engine) -> None:
    factory = session_factory(engine)
    executor = RecordingExecutor(succeeded=False, reason="target_unreachable")
    with factory() as session:
        engagement_id = seed_engagement(session)
        mission = seed_mission(session, engagement_id)
        lead = seed_lead(session, engagement_id, MissionId(mission.id))
        session.commit()

        controller = build_controller(session, MissionId(mission.id), executor=executor)
        report = controller.run_cycle(controller.start_run())
        stored = LeadRepository(session).get(LeadId(lead.id))

    assert report.outcomes[0].disposition == "failed"
    assert stored is not None
    assert stored.entity.status is LeadStatus.WAITING
    assert stored.entity.failure_count == 1
    assert stored.entity.next_attempt_at is not None


def test_surface_change_reawakens_a_stale_lead(engine: Engine) -> None:
    factory = session_factory(engine)
    executor = RecordingExecutor()
    with factory() as session:
        engagement_id = seed_engagement(session)
        mission = seed_mission(session, engagement_id)
        lead = seed_lead(
            session,
            engagement_id,
            MissionId(mission.id),
            status=LeadStatus.STALE,
        )
        seed_surface(session, engagement_id, at=NOW - timedelta(days=1))
        session.commit()

        baseline = build_controller(session, MissionId(mission.id), executor=executor)
        baseline.run_cycle(baseline.start_run())  # baseline snapshot at NOW

        later = NOW + timedelta(minutes=10)
        seed_surface(session, engagement_id, at=later, path="/invoices")
        session.commit()

        controller = build_controller(
            session, MissionId(mission.id), executor=executor, now=later
        )
        report = controller.run_cycle(controller.start_run())
        stored = LeadRepository(session).get(LeadId(lead.id))

    assert report.changes_detected == 1
    assert stored is not None
    assert stored.entity.status is not LeadStatus.STALE


def test_each_attempt_uses_a_distinct_idempotency_key(engine: Engine) -> None:
    factory = session_factory(engine)
    executor = RecordingExecutor()
    with factory() as session:
        engagement_id = seed_engagement(session)
        mission = seed_mission(
            session,
            engagement_id,
            cadence=MissionCadence(lead_retry_cooldown_seconds=30),
        )
        lead = seed_lead(session, engagement_id, MissionId(mission.id))
        session.commit()

        controller = build_controller(session, MissionId(mission.id), executor=executor)
        controller.run_cycle(controller.start_run())

        stored = LeadRepository(session).get(LeadId(lead.id))
        assert stored is not None
        LeadRepository(session).save(
            replace(stored.entity, status=LeadStatus.QUEUED, next_attempt_at=None),
            expected_version=stored.version,
        )
        session.commit()

        controller.run_cycle(controller.start_run())
        keys = [
            item.entity.idempotency_key
            for item in ActionRepository(session).list_for_engagement(engagement_id)
        ]

    assert len(keys) == len(set(keys)) == 2
    assert all(TARGET_HOST not in key for key in keys)
