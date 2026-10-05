"""Tests for reconnaissance, probing and candidate recording inside the mission cycle.

These close the loop: a bundle is read, endpoints are recovered and classified, the safe
ones are probed, and a machine-judged observation becomes work the controller will pick
up on a later cycle — all without a human between the steps.
"""

from __future__ import annotations

import json
from collections.abc import Generator, Sequence
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from pathlib import Path

import pytest
from sqlalchemy import Engine, text

from tests.agent.support import (
    NOW,
    TARGET_HOST,
    build_engine,
    seed_engagement,
    seed_lead,
    seed_mission,
    session_factory,
)
from tests.agent.test_controller import RecordingExecutor, frozen_clock
from vuln_proof_claw.agent.budget import BudgetGate
from vuln_proof_claw.agent.controller import MissionController
from vuln_proof_claw.agent.differential import OracleRule, OracleVerdict
from vuln_proof_claw.agent.endpoints import EndpointClassification, classify_all
from vuln_proof_claw.agent.planner import DeterministicPlanner
from vuln_proof_claw.agent.recon import ReconResult
from vuln_proof_claw.agent.sweep import EndpointSpec, ProbeOutcome
from vuln_proof_claw.domain.autonomous import MissionBudget, MissionCadence
from vuln_proof_claw.domain.enums import LeadStatus
from vuln_proof_claw.domain.identifiers import MissionId
from vuln_proof_claw.persistence.autonomous_repositories import (
    EndpointRepository,
    LeadRepository,
    MissionRepository,
)

TARGET = f"https://{TARGET_HOST}:443/api/getCompanyDisplay"


@pytest.fixture
def engine(tmp_path: Path) -> Generator[Engine, None, None]:
    yield from build_engine(tmp_path / "controller_recon.db")


@dataclass
class StubRecon:
    """Returns a canned inventory, or raises, to test containment."""

    classifications: tuple[EndpointClassification, ...] = field(default_factory=tuple)
    explode: bool = False
    calls: int = 0
    requests_sent: int = 0

    def discover(self, *, at: datetime) -> ReconResult:
        self.calls += 1
        if self.explode:
            raise RuntimeError("bundle unreachable")
        return ReconResult(
            base_url=f"https://{TARGET_HOST}/",
            classifications=self.classifications,
            # Spread across minutes, as a paced reconnaissance pass really is.
            sent_at=tuple(
                at + timedelta(seconds=30 * index) for index in range(self.requests_sent)
            ),
        )


def recon_for(*paths: tuple[str, str]) -> StubRecon:
    return StubRecon(classifications=classify_all(paths))


@dataclass
class StubProber:
    """Records the plan it was handed and returns canned verdicts."""

    verdicts: tuple[OracleVerdict, ...] = field(default_factory=tuple)
    requests_sent: int = 0
    explode: bool = False
    plans: list[tuple[EndpointSpec, ...]] = field(default_factory=list)

    def probe(self, endpoints: Sequence[EndpointSpec], *, at: datetime) -> ProbeOutcome:
        self.plans.append(tuple(endpoints))
        if self.explode:
            raise RuntimeError("target unreachable")
        count = self.requests_sent or len(endpoints)
        # A real sweep paces itself, so the times it reports span minutes.
        return ProbeOutcome(
            verdicts=self.verdicts,
            sent_at=tuple(at + timedelta(seconds=20 * index) for index in range(count)),
        )


def controller_with(  # noqa: PLR0913 - explicit collaborators keep the setup readable
    session: object,
    mission_id: MissionId,
    *,
    executor: RecordingExecutor,
    recon: StubRecon | None = None,
    prober: StubProber | None = None,
    probe_mutating: bool = False,
) -> MissionController:
    return MissionController(
        session,  # type: ignore[arg-type]
        mission_id,
        planner=DeterministicPlanner(),
        executor=executor,
        clock=frozen_clock(),  # type: ignore[arg-type]
        reconnaissance=recon,
        prober=prober,
        probe_mutating=probe_mutating,
    )


def triggered_verdict(target: str = TARGET) -> OracleVerdict:
    return OracleVerdict(
        OracleRule.MISSING_AUTHENTICATION,
        triggered=True,
        target=target,
        reason="an unauthenticated request received 200 with a 94-byte response",
    )


def test_reconnaissance_records_endpoints_into_the_knowledge_base(engine: Engine) -> None:
    factory = session_factory(engine)
    executor = RecordingExecutor()
    recon = recon_for(
        ("GET", "/api/getCompanyDisplay"),
        ("POST", "/api/setDeviceMessage"),
        ("POST", "/api/setDeviceSecureWipe"),
    )
    with factory() as session:
        engagement_id = seed_engagement(session)
        mission = seed_mission(session, engagement_id)
        session.commit()

        controller = controller_with(
            session, MissionId(mission.id), executor=executor, recon=recon
        )
        report = controller.run_cycle(controller.start_run())
        stored = EndpointRepository(session).count(engagement_id)

    assert recon.calls == 1
    assert report.recon.endpoints_recorded == 3
    assert report.recon.endpoints_held_back == 1
    assert stored == 3


def test_reconnaissance_requests_reach_the_budget_ledger(engine: Engine) -> None:
    """A pass that spends nine requests must leave nine in the ledger, or the mission
    under-reports how much it touched the target."""
    factory = session_factory(engine)
    recon = recon_for(("GET", "/api/getCompanyDisplay"))
    recon.requests_sent = 9
    with factory() as session:
        engagement_id = seed_engagement(session)
        mission = seed_mission(
            session, engagement_id, budget=MissionBudget(requests_per_hour=100)
        )
        session.commit()

        controller = controller_with(
            session, MissionId(mission.id), executor=RecordingExecutor(), recon=recon
        )
        report = controller.run_cycle(controller.start_run())
        reloaded = MissionRepository(session).get(MissionId(mission.id))
        assert reloaded is not None
        remaining = BudgetGate(session, reloaded.entity).sustained_requests(at=NOW)

    assert report.recon.requests_sent == 9
    assert remaining == 100 - 9


def test_a_paced_batch_is_not_recorded_as_a_burst(engine: Engine) -> None:
    """Charging a paced batch to one instant writes a burst that never happened.

    Six requests spread over three minutes must not read as six in one, or the ledger
    claims the mission exceeded a rate limit the wire never exceeded — and the ledger
    is the mission's answer to how hard it hit the host.
    """
    factory = session_factory(engine)
    recon = recon_for(("GET", "/api/getCompanyDisplay"))
    recon.requests_sent = 6  # the stub spreads these 30 seconds apart
    with factory() as session:
        engagement_id = seed_engagement(session)
        mission = seed_mission(
            session,
            engagement_id,
            budget=MissionBudget(requests_per_minute_per_domain=3, requests_per_hour=100),
        )
        session.commit()

        controller = controller_with(
            session, MissionId(mission.id), executor=RecordingExecutor(), recon=recon
        )
        controller.run_cycle(controller.start_run())
        rows = session.execute(
            text(
                "select window_start, request_count from budget_ledger "
                "where window_kind = 'minute' order by window_start"
            )
        ).all()

    # Six requests, thirty seconds apart, land across three separate minutes.
    assert len(rows) == 3
    assert [count for _, count in rows] == [2, 2, 2]


def test_the_sweep_audit_records_when_it_finished_and_its_span(engine: Engine) -> None:
    """A paced sweep runs for half an hour; stamping it at the cycle's start time
    tells an auditor that every request happened in one instant."""
    factory = session_factory(engine)
    prober = StubProber(requests_sent=4)  # the stub spreads these 20 seconds apart
    with factory() as session:
        engagement_id = seed_engagement(session)
        mission = seed_mission(session, engagement_id)
        session.commit()

        controller = controller_with(
            session,
            MissionId(mission.id),
            executor=RecordingExecutor(),
            recon=recon_for(("GET", "/api/getA")),
            prober=prober,
        )
        controller.run_cycle(controller.start_run())
        payload = session.execute(
            text(
                "select payload from audit_events "
                "where event_type = 'agent.sweep_completed'"
            )
        ).scalar_one()

    recorded = payload if isinstance(payload, dict) else json.loads(payload)
    assert recorded["first_request_at"] != recorded["last_request_at"]
    assert recorded["requests_sent"] == 4


def test_a_failing_reconnaissance_does_not_fail_the_cycle(engine: Engine) -> None:
    """Losing one pass costs a delay; aborting would abandon the waiting leads too."""
    factory = session_factory(engine)
    executor = RecordingExecutor()
    with factory() as session:
        engagement_id = seed_engagement(session)
        mission = seed_mission(session, engagement_id)
        seed_lead(session, engagement_id, MissionId(mission.id))
        session.commit()

        controller = controller_with(
            session,
            MissionId(mission.id),
            executor=executor,
            recon=StubRecon(explode=True),
        )
        report = controller.run_cycle(controller.start_run())

    assert report.recon.skipped == "reconnaissance_failed"
    assert report.outcomes
    assert len(executor.executed) == 1


def test_reconnaissance_is_skipped_when_not_configured(engine: Engine) -> None:
    factory = session_factory(engine)
    with factory() as session:
        engagement_id = seed_engagement(session)
        mission = seed_mission(session, engagement_id)
        session.commit()

        controller = controller_with(
            session, MissionId(mission.id), executor=RecordingExecutor()
        )
        report = controller.run_cycle(controller.start_run())

    assert report.recon.skipped == "no_reconnaissance_configured"


def test_reconnaissance_respects_the_inventory_cadence(engine: Engine) -> None:
    """Refetching a bundle every few minutes is the repetition the rules forbid."""
    factory = session_factory(engine)
    recon = recon_for(("GET", "/api/getCompanyDisplay"))
    with factory() as session:
        engagement_id = seed_engagement(session)
        mission = seed_mission(
            session, engagement_id, cadence=MissionCadence(http_inventory_seconds=3_600)
        )
        session.commit()

        controller = controller_with(
            session, MissionId(mission.id), executor=RecordingExecutor(), recon=recon
        )
        first = controller.run_cycle(controller.start_run())
        second = controller.run_cycle(first.run)

    assert recon.calls == 1
    assert first.recon.endpoints_recorded == 1
    assert second.recon.skipped == "interval_pending"


def test_an_empty_inventory_is_reported_not_recorded(engine: Engine) -> None:
    factory = session_factory(engine)
    with factory() as session:
        engagement_id = seed_engagement(session)
        mission = seed_mission(session, engagement_id)
        session.commit()

        controller = controller_with(
            session, MissionId(mission.id), executor=RecordingExecutor(), recon=StubRecon()
        )
        report = controller.run_cycle(controller.start_run())

    assert report.recon.skipped == "no_endpoints_recovered"


def test_one_cycle_goes_from_a_bundle_to_a_lead(engine: Engine) -> None:
    """The whole chain, unattended: discover, classify, probe, judge, record."""
    factory = session_factory(engine)
    recon = recon_for(
        ("GET", "/api/getCompanyDisplay"),
        ("POST", "/api/setDeviceSecureWipe"),
    )
    prober = StubProber(verdicts=(triggered_verdict(),))
    with factory() as session:
        engagement_id = seed_engagement(session)
        mission = seed_mission(session, engagement_id)
        session.commit()

        controller = controller_with(
            session,
            MissionId(mission.id),
            executor=RecordingExecutor(),
            recon=recon,
            prober=prober,
        )
        report = controller.run_cycle(controller.start_run())
        worked = LeadRepository(session).list_by_status(
            MissionId(mission.id), (LeadStatus.WAITING,)
        )

    assert report.recon.endpoints_recorded == 2
    assert report.sweep.endpoints_probed == 1
    assert report.sweep.verdicts_triggered == 1
    assert report.sweep.leads_created == 1
    # The lead the sweep raised is picked up by the same cycle that raised it, so a
    # finding does not wait for the next pass to be investigated.
    assert [outcome.disposition for outcome in report.outcomes] == ["executed"]
    assert len(worked) == 1


def test_a_destructive_endpoint_is_never_handed_to_the_prober(engine: Engine) -> None:
    """The strongest guarantee in the loop: it has to hold at the boundary, not above it."""
    factory = session_factory(engine)
    prober = StubProber()
    with factory() as session:
        engagement_id = seed_engagement(session)
        mission = seed_mission(session, engagement_id)
        session.commit()

        controller = controller_with(
            session,
            MissionId(mission.id),
            executor=RecordingExecutor(),
            recon=recon_for(
                ("POST", "/api/setDeviceSecureWipe"),
                ("POST", "/api/deleteAccount"),
                ("GET", "/api/getCompanyDisplay"),
            ),
            prober=prober,
        )
        report = controller.run_cycle(controller.start_run())

    assert [spec.path for spec in prober.plans[0]] == ["/api/getCompanyDisplay"]
    assert report.sweep.endpoints_withheld == 2


@pytest.mark.parametrize(
    ("opt_in", "expected"), [(False, 0), (True, 1)], ids=["withheld", "opted-in"]
)
def test_a_mutating_endpoint_waits_for_an_operator(
    engine: Engine, *, opt_in: bool, expected: int
) -> None:
    """An empty-body POST to setX is still a write; L1 does not authorize it."""
    factory = session_factory(engine)
    prober = StubProber()
    with factory() as session:
        engagement_id = seed_engagement(session)
        mission = seed_mission(session, engagement_id)
        session.commit()

        controller = controller_with(
            session,
            MissionId(mission.id),
            executor=RecordingExecutor(),
            recon=recon_for(("POST", "/api/setDeviceMessage")),
            prober=prober,
            probe_mutating=opt_in,
        )
        report = controller.run_cycle(controller.start_run())

    assert report.sweep.endpoints_probed == expected
    assert len(prober.plans[0] if prober.plans else ()) == expected


def test_a_failing_prober_does_not_fail_the_cycle(engine: Engine) -> None:
    factory = session_factory(engine)
    with factory() as session:
        engagement_id = seed_engagement(session)
        mission = seed_mission(session, engagement_id)
        seed_lead(session, engagement_id, MissionId(mission.id))
        session.commit()

        controller = controller_with(
            session,
            MissionId(mission.id),
            executor=RecordingExecutor(),
            recon=recon_for(("GET", "/api/getCompanyDisplay")),
            prober=StubProber(explode=True),
        )
        report = controller.run_cycle(controller.start_run())

    assert report.sweep.skipped == "sweep_failed"
    assert report.outcomes


def test_probing_is_skipped_when_no_prober_is_configured(engine: Engine) -> None:
    factory = session_factory(engine)
    with factory() as session:
        engagement_id = seed_engagement(session)
        mission = seed_mission(session, engagement_id)
        session.commit()

        controller = controller_with(
            session, MissionId(mission.id), executor=RecordingExecutor()
        )
        report = controller.run_cycle(controller.start_run())

    assert report.sweep.skipped == "no_prober_configured"


def test_nothing_is_probed_before_anything_is_discovered(engine: Engine) -> None:
    factory = session_factory(engine)
    with factory() as session:
        engagement_id = seed_engagement(session)
        mission = seed_mission(session, engagement_id)
        session.commit()

        controller = controller_with(
            session,
            MissionId(mission.id),
            executor=RecordingExecutor(),
            prober=StubProber(),
        )
        report = controller.run_cycle(controller.start_run())

    assert report.sweep.skipped == "no_endpoints_known"


def test_the_sweep_plan_is_bounded_by_the_remaining_request_budget(
    engine: Engine,
) -> None:
    """A sweep commits to a plan up front, so the headroom has to bound the plan.

    The per-minute rate is deliberately tight here and must not bound it: the sweep
    paces itself across minutes, so the hourly ceiling is what limits the plan's size.
    """
    factory = session_factory(engine)
    prober = StubProber()
    with factory() as session:
        engagement_id = seed_engagement(session)
        mission = seed_mission(
            session,
            engagement_id,
            budget=MissionBudget(requests_per_minute_per_domain=1, requests_per_hour=2),
        )
        session.commit()

        controller = controller_with(
            session,
            MissionId(mission.id),
            executor=RecordingExecutor(),
            recon=recon_for(
                ("GET", "/api/getA"),
                ("GET", "/api/getB"),
                ("GET", "/api/getC"),
                ("GET", "/api/getD"),
            ),
            prober=prober,
        )
        report = controller.run_cycle(controller.start_run())

    assert len(prober.plans[0]) == 2
    assert report.sweep.endpoints_withheld == 2


def test_the_budget_is_charged_for_what_was_actually_sent(engine: Engine) -> None:
    """A sweep that stopped early must not be billed for the plan it abandoned."""
    factory = session_factory(engine)
    with factory() as session:
        engagement_id = seed_engagement(session)
        mission = seed_mission(
            session, engagement_id, budget=MissionBudget(requests_per_hour=10)
        )
        session.commit()

        controller = controller_with(
            session,
            MissionId(mission.id),
            executor=RecordingExecutor(),
            recon=recon_for(("GET", "/api/getA"), ("GET", "/api/getB")),
            prober=StubProber(requests_sent=3),
        )
        report = controller.run_cycle(controller.start_run())

    assert report.sweep.requests_sent == 3


def test_probing_respects_its_own_cadence(engine: Engine) -> None:
    """Re-probing every cycle is the repetition the activity rules forbid."""
    factory = session_factory(engine)
    prober = StubProber()
    with factory() as session:
        engagement_id = seed_engagement(session)
        mission = seed_mission(
            session,
            engagement_id,
            cadence=MissionCadence(http_inventory_seconds=3_600, deep_recon_seconds=7_200),
        )
        session.commit()

        controller = controller_with(
            session,
            MissionId(mission.id),
            executor=RecordingExecutor(),
            recon=recon_for(("GET", "/api/getCompanyDisplay")),
            prober=prober,
        )
        first = controller.run_cycle(controller.start_run())
        second = controller.run_cycle(first.run)

    assert len(prober.plans) == 1
    assert first.sweep.endpoints_probed == 1
    assert second.sweep.skipped == "interval_pending"


def test_verdicts_become_candidates_and_schedulable_leads(engine: Engine) -> None:
    """The last rung: a machine-judged observation becomes work the loop picks up."""
    factory = session_factory(engine)
    verdict = OracleVerdict(
        OracleRule.MISSING_AUTHENTICATION,
        triggered=True,
        target=TARGET,
        reason="an unauthenticated request received 200 with a 94-byte response",
    )
    with factory() as session:
        engagement_id = seed_engagement(session)
        mission = seed_mission(session, engagement_id)
        session.commit()

        controller = controller_with(
            session, MissionId(mission.id), executor=RecordingExecutor()
        )
        summary = controller.record_observations([verdict], at=NOW)
        leads = LeadRepository(session).list_by_status(
            MissionId(mission.id), (LeadStatus.NEW,)
        )

    assert summary.candidates_created == 1
    assert summary.leads_created == 1
    assert len(leads) == 1
    assert leads[0].entity.next_action == TARGET


def test_a_promoted_lead_states_it_is_unverified(engine: Engine) -> None:
    """A candidate asserts a rule fired, not that a vulnerability exists."""
    factory = session_factory(engine)
    verdict = OracleVerdict(
        OracleRule.MISSING_AUTHENTICATION, triggered=True, target=TARGET, reason="observed"
    )
    with factory() as session:
        engagement_id = seed_engagement(session)
        mission = seed_mission(session, engagement_id)
        session.commit()

        controller = controller_with(
            session, MissionId(mission.id), executor=RecordingExecutor()
        )
        controller.record_observations([verdict], at=NOW)
        leads = LeadRepository(session).list_by_status(
            MissionId(mission.id), (LeadStatus.NEW,)
        )

    assert "尚未經研究員驗證" in leads[0].entity.hypothesis


def test_repeating_a_verdict_does_not_duplicate_work(engine: Engine) -> None:
    factory = session_factory(engine)
    verdict = OracleVerdict(
        OracleRule.MISSING_AUTHENTICATION,
        triggered=True,
        target=f"https://{TARGET_HOST}:443/api/x",
        reason="observed",
    )
    with factory() as session:
        engagement_id = seed_engagement(session)
        mission = seed_mission(session, engagement_id)
        session.commit()

        controller = controller_with(
            session, MissionId(mission.id), executor=RecordingExecutor()
        )
        first = controller.record_observations([verdict], at=NOW)
        second = controller.record_observations([verdict], at=NOW)

    assert first.leads_created == 1
    assert second.candidates_created == 0
    assert second.leads_created == 0


def test_a_clear_verdict_creates_nothing(engine: Engine) -> None:
    factory = session_factory(engine)
    verdict = OracleVerdict(
        OracleRule.MISSING_AUTHENTICATION,
        triggered=False,
        target=TARGET,
        reason="correctly refused with 401",
    )
    with factory() as session:
        engagement_id = seed_engagement(session)
        mission = seed_mission(session, engagement_id)
        session.commit()

        controller = controller_with(
            session, MissionId(mission.id), executor=RecordingExecutor()
        )
        summary = controller.record_observations([verdict], at=NOW)

    assert summary.candidates_created == 0
    assert summary.leads_created == 0
