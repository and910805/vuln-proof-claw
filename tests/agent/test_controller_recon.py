"""Tests for reconnaissance, probing and candidate recording inside the mission cycle.

These close the loop: a bundle is read, endpoints are recovered and classified, the safe
ones are probed, and a machine-judged observation becomes work the controller will pick
up on a later cycle — all without a human between the steps.
"""

from __future__ import annotations

import json
from collections.abc import Callable, Generator, Sequence
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
# Past the default http_inventory cadence, so a second pass is due.
LATER = NOW + timedelta(hours=1)


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
    source: str = "jsdiscovery"
    errors: tuple[str, ...] = ()
    base_url: str = f"https://{TARGET_HOST}/"

    def discover(self, *, at: datetime) -> ReconResult:
        self.calls += 1
        if self.explode:
            raise RuntimeError("bundle unreachable")
        return ReconResult(
            base_url=self.base_url,
            classifications=self.classifications,
            source=self.source,
            errors=self.errors,
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

    def probe(
        self,
        endpoints: Sequence[EndpointSpec],
        *,
        at: datetime,
        on_request: Callable[[datetime], None] | None = None,
    ) -> ProbeOutcome:
        self.plans.append(tuple(endpoints))
        if self.explode:
            raise RuntimeError("target unreachable")
        count = self.requests_sent or len(endpoints)
        # A real sweep reports each request as it goes out, so the budget is charged
        # while the sweep is still running rather than all at once at the end.
        if on_request is not None:
            for index in range(count):
                on_request(at + timedelta(seconds=20 * index))
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
    now: datetime = NOW,
    recon_sources: Sequence[StubRecon] | None = None,
) -> MissionController:
    return MissionController(
        session,  # type: ignore[arg-type]
        mission_id,
        planner=DeterministicPlanner(),
        executor=executor,
        clock=frozen_clock(now),  # type: ignore[arg-type]
        reconnaissance=recon_sources if recon_sources is not None else recon,
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


def observed_recon(*paths: tuple[str, str]) -> StubRecon:
    """Reconnaissance that saw these leave, rather than reading them from source."""
    stub = StubRecon(classifications=classify_all(paths))
    stub.source = "observed"
    return stub


def test_paths_read_from_source_are_corrected_by_what_was_observed(
    engine: Engine,
) -> None:
    """A client written against /web/x calls /api/web/x. Every inferred path is wrong
    the same way, and probing them yields a tidy page of "no handler reached"."""
    factory = session_factory(engine)
    with factory() as session:
        engagement_id = seed_engagement(session)
        mission = seed_mission(session, engagement_id)
        session.commit()

        # First the browser sees three calls go out.
        seen = observed_recon(
            ("GET", "/api/web/alpha"),
            ("GET", "/api/web/beta"),
            ("GET", "/api/web/gamma"),
        )
        controller = controller_with(
            session, MissionId(mission.id), executor=RecordingExecutor(), recon=seen
        )
        controller.run_cycle(controller.start_run())

        # Then, a cadence later, the bundle is read and describes them without it.
        inferred = recon_for(
            ("GET", "/web/alpha"),
            ("GET", "/web/beta"),
            ("GET", "/web/gamma"),
            ("GET", "/web/delta"),
        )
        controller = controller_with(
            session,
            MissionId(mission.id),
            executor=RecordingExecutor(),
            recon=inferred,
            now=LATER,
        )
        controller.run_cycle(controller.start_run())

        stored = {
            item.entity.path
            for item in EndpointRepository(session).list_for_engagement(engagement_id)
        }

    # The one the browser never saw is corrected too, on the strength of the three it did.
    assert "/api/web/delta" in stored
    assert "/web/delta" not in stored


def test_without_enough_observations_nothing_is_rewritten(engine: Engine) -> None:
    """One agreement can be coincidence, and a prefix applied on that basis turns one
    set of wrong paths into another while making them look confirmed."""
    factory = session_factory(engine)
    with factory() as session:
        engagement_id = seed_engagement(session)
        mission = seed_mission(session, engagement_id)
        session.commit()

        controller = controller_with(
            session,
            MissionId(mission.id),
            executor=RecordingExecutor(),
            recon=observed_recon(("GET", "/api/web/alpha")),
        )
        controller.run_cycle(controller.start_run())

        controller = controller_with(
            session,
            MissionId(mission.id),
            executor=RecordingExecutor(),
            recon=recon_for(("GET", "/web/alpha"), ("GET", "/web/delta")),
            now=LATER,
        )
        controller.run_cycle(controller.start_run())

        stored = {
            item.entity.path
            for item in EndpointRepository(session).list_for_engagement(engagement_id)
        }

    assert "/web/delta" in stored
    assert "/api/web/delta" not in stored


def test_an_observation_is_recorded_as_observed(engine: Engine) -> None:
    """Reconciliation needs to tell an inference from a fact, so the store must say."""
    factory = session_factory(engine)
    with factory() as session:
        engagement_id = seed_engagement(session)
        mission = seed_mission(session, engagement_id)
        session.commit()

        controller = controller_with(
            session,
            MissionId(mission.id),
            executor=RecordingExecutor(),
            recon=observed_recon(("GET", "/api/web/alpha")),
        )
        controller.run_cycle(controller.start_run())

        sources = {
            item.entity.source
            for item in EndpointRepository(session).list_for_engagement(engagement_id)
        }

    # The label carries the discovery source and what the classifier made of it;
    # reconciliation reads the source half.
    assert sources == {"observed:read"}


def test_one_cycle_uses_every_configured_source(engine: Engine) -> None:
    """Both sources in a single pass, so nobody has to launch the agent twice in the
    right order to get a surface that is both complete and correctly addressed."""
    factory = session_factory(engine)
    with factory() as session:
        engagement_id = seed_engagement(session)
        mission = seed_mission(session, engagement_id)
        session.commit()

        # Configured inference-first, which is the order that would not work if the
        # controller simply ran them as given.
        inferred = recon_for(
            ("GET", "/web/alpha"),
            ("GET", "/web/beta"),
            ("GET", "/web/gamma"),
            ("GET", "/web/delta"),
        )
        seen = observed_recon(
            ("GET", "/api/web/alpha"),
            ("GET", "/api/web/beta"),
            ("GET", "/api/web/gamma"),
        )
        controller = controller_with(
            session,
            MissionId(mission.id),
            executor=RecordingExecutor(),
            recon_sources=(inferred, seen),
        )
        controller.run_cycle(controller.start_run())

        stored = {
            item.entity.path
            for item in EndpointRepository(session).list_for_engagement(engagement_id)
        }

    assert inferred.calls == 1
    assert seen.calls == 1
    assert "/api/web/delta" in stored
    assert "/web/delta" not in stored


def test_one_source_failing_does_not_lose_the_other(engine: Engine) -> None:
    """A browser that is not installed should cost the browser's contribution, not the
    cycle's."""
    factory = session_factory(engine)
    with factory() as session:
        engagement_id = seed_engagement(session)
        mission = seed_mission(session, engagement_id)
        session.commit()

        controller = controller_with(
            session,
            MissionId(mission.id),
            executor=RecordingExecutor(),
            recon_sources=(StubRecon(explode=True), recon_for(("GET", "/web/alpha"))),
        )
        report = controller.run_cycle(controller.start_run())

        stored = {
            item.entity.path
            for item in EndpointRepository(session).list_for_engagement(engagement_id)
        }

    assert report.recon.skipped is None
    assert stored == {"/web/alpha"}


def test_a_pass_that_recovered_nothing_records_why(engine: Engine) -> None:
    """One target's certificate was not trusted. Both sources refused it and returned
    errors rather than raising, so nothing was written, and the knowledge base showed a
    target with no surface and no explanation -- which is what a safe target looks
    like too."""
    factory = session_factory(engine)
    with factory() as session:
        engagement_id = seed_engagement(session)
        mission = seed_mission(session, engagement_id)
        session.commit()

        barren = StubRecon()
        barren.errors = ("ERR_CERT_AUTHORITY_INVALID at https://target.test/",)
        controller = controller_with(
            session, MissionId(mission.id), executor=RecordingExecutor(), recon=barren
        )
        controller.run_cycle(controller.start_run())

        recorded = [
            json.loads(row[0])
            for row in session.execute(
                text("select payload from audit_events where event_type = 'agent.recon_empty'")
            )
        ]

    assert recorded, "a pass that found nothing left no trace"
    assert "ERR_CERT_AUTHORITY_INVALID" in recorded[0]["errors"]


def test_an_empty_pass_with_no_errors_still_says_so(engine: Engine) -> None:
    """A target that genuinely has no recoverable surface is a different fact from a
    target nobody could reach, and both have to be distinguishable afterwards."""
    factory = session_factory(engine)
    with factory() as session:
        engagement_id = seed_engagement(session)
        mission = seed_mission(session, engagement_id)
        session.commit()

        controller = controller_with(
            session, MissionId(mission.id), executor=RecordingExecutor(), recon=StubRecon()
        )
        controller.run_cycle(controller.start_run())

        recorded = [
            json.loads(row[0])
            for row in session.execute(
                text("select payload from audit_events where event_type = 'agent.recon_empty'")
            )
        ]

    assert recorded[0]["errors"] == "no endpoints recovered"


def test_pointing_a_source_somewhere_new_makes_reconnaissance_due(engine: Engine) -> None:
    """Two targets were registered at their web server's root, which served the IIS
    welcome page, and both were recorded as having one endpoint. The cadence exists so
    the same bundle is not refetched every few minutes; a different entry URL is a
    different question, and waiting an hour to ask it is an hour of the old answer."""
    factory = session_factory(engine)
    with factory() as session:
        engagement_id = seed_engagement(session)
        mission = seed_mission(session, engagement_id)
        session.commit()

        first = recon_for(("GET", "/"))
        controller = controller_with(
            session, MissionId(mission.id), executor=RecordingExecutor(), recon=first
        )
        controller.run_cycle(controller.start_run())

        # Same moment, so the cadence has certainly not elapsed.
        moved = recon_for(("GET", "/portal/login.aspx"))
        moved.base_url = f"https://{TARGET_HOST}/portal/"
        controller = controller_with(
            session, MissionId(mission.id), executor=RecordingExecutor(), recon=moved
        )
        controller.run_cycle(controller.start_run())

        stored = {
            item.entity.path
            for item in EndpointRepository(session).list_for_engagement(engagement_id)
        }

    assert moved.calls == 1, "the corrected entry URL was not visited"
    assert "/portal/login.aspx" in stored


def test_the_same_entry_url_still_waits_for_the_cadence(engine: Engine) -> None:
    """The rule being relaxed is about repeating the same question, and that rule
    stays: an unchanged entry must not be refetched every cycle."""
    factory = session_factory(engine)
    with factory() as session:
        engagement_id = seed_engagement(session)
        mission = seed_mission(session, engagement_id)
        session.commit()

        first = recon_for(("GET", "/"))
        controller = controller_with(
            session, MissionId(mission.id), executor=RecordingExecutor(), recon=first
        )
        controller.run_cycle(controller.start_run())

        again = recon_for(("GET", "/"))
        controller = controller_with(
            session, MissionId(mission.id), executor=RecordingExecutor(), recon=again
        )
        report = controller.run_cycle(controller.start_run())

    assert again.calls == 0
    assert report.recon.skipped is not None


def test_a_skipped_sweep_says_why(engine: Engine) -> None:
    """Two targets recovered 251 and 53 endpoints and probed none of them, with nothing
    in the database between the reconnaissance and the end of the run. Reconnaissance
    had spent the request budget -- the budget working as intended -- and from the
    outside that is indistinguishable from a target with nothing worth asking."""
    factory = session_factory(engine)
    with factory() as session:
        engagement_id = seed_engagement(session)
        mission = seed_mission(
            session, engagement_id, budget=MissionBudget(requests_per_hour=2)
        )
        session.commit()

        # Reconnaissance spends the hour's whole allowance, exactly as it did live.
        spent = recon_for(("GET", "/api/alpha"), ("GET", "/api/beta"))
        spent.requests_sent = 2
        controller = controller_with(
            session,
            MissionId(mission.id),
            executor=RecordingExecutor(),
            recon=spent,
            prober=StubProber(),
        )
        report = controller.run_cycle(controller.start_run())

        recorded = [
            json.loads(row[0])
            for row in session.execute(
                text("select payload from audit_events where event_type='agent.sweep_skipped'")
            )
        ]

    assert report.sweep.skipped is not None
    assert recorded, "a sweep that did not happen left no trace"
    assert recorded[0]["reason"] == report.sweep.skipped


def test_a_sweep_that_ran_records_no_skip(engine: Engine) -> None:
    factory = session_factory(engine)
    with factory() as session:
        engagement_id = seed_engagement(session)
        mission = seed_mission(session, engagement_id)
        session.commit()

        controller = controller_with(
            session,
            MissionId(mission.id),
            executor=RecordingExecutor(),
            recon=recon_for(("GET", "/api/alpha")),
            prober=StubProber(),
        )
        controller.run_cycle(controller.start_run())

        skipped = session.execute(
            text("select count(*) from audit_events where event_type='agent.sweep_skipped'")
        ).scalar_one()

    assert skipped == 0


def test_endpoints_nobody_has_asked_anything_do_not_wait_for_the_cadence(
    engine: Engine,
) -> None:
    """Reconciliation corrected 195 inferred paths onto the prefix the client actually
    prepends -- the entire point of building it -- and the sweep then declined them for
    twenty-four hours because it had run that morning against the uncorrected ones.

    The cadence governs how often the same questions are re-asked. An endpoint nothing
    has ever asked is not the same question."""
    factory = session_factory(engine)
    with factory() as session:
        engagement_id = seed_engagement(session)
        mission = seed_mission(session, engagement_id)
        session.commit()

        first = StubProber()
        controller = controller_with(
            session,
            MissionId(mission.id),
            executor=RecordingExecutor(),
            recon=recon_for(("GET", "/web/alpha")),
            prober=first,
        )
        controller.run_cycle(controller.start_run())
        assert first.plans, "the first sweep did not run"

        # A later cycle, within the sweep interval, after discovery found more.
        second = StubProber()
        controller = controller_with(
            session,
            MissionId(mission.id),
            executor=RecordingExecutor(),
            recon=recon_for(("GET", "/web/alpha"), ("GET", "/web/beta")),
            prober=second,
            now=NOW + timedelta(hours=2),
        )
        controller.run_cycle(controller.start_run())

    assert second.plans, "endpoints discovered since the last sweep went unprobed"
    assert any(
        spec.path == "/web/beta" for plan in second.plans for spec in plan
    )


def test_an_unchanged_inventory_still_waits(engine: Engine) -> None:
    """The restraint being relaxed is about re-asking, and that stays."""
    factory = session_factory(engine)
    with factory() as session:
        engagement_id = seed_engagement(session)
        mission = seed_mission(session, engagement_id)
        session.commit()

        controller = controller_with(
            session,
            MissionId(mission.id),
            executor=RecordingExecutor(),
            recon=recon_for(("GET", "/web/alpha")),
            prober=StubProber(),
        )
        controller.run_cycle(controller.start_run())

        later = StubProber()
        controller = controller_with(
            session,
            MissionId(mission.id),
            executor=RecordingExecutor(),
            recon=recon_for(("GET", "/web/alpha")),
            prober=later,
            now=NOW + timedelta(hours=2),
        )
        report = controller.run_cycle(controller.start_run())

    assert later.plans == []
    assert report.sweep.skipped is not None


def test_no_record_of_looking_anywhere_counts_as_somewhere_new(engine: Engine) -> None:
    """An earlier version required a record to exist before a change could be noticed,
    meaning to be careful about databases written before the field did. That is exactly
    the state of every target whose entry URL needs correcting, so the correction could
    fire for none of them: four stayed at one endpoint each through two passes."""
    factory = session_factory(engine)
    with factory() as session:
        engagement_id = seed_engagement(session)
        mission = seed_mission(session, engagement_id)
        session.commit()

        controller = controller_with(
            session, MissionId(mission.id), executor=RecordingExecutor(),
            recon=recon_for(("GET", "/")),
        )
        controller.run_cycle(controller.start_run())

        # A record as an older release wrote it: no base_url at all.
        session.execute(
            text("update audit_events set payload = :body where event_type = :kind"),
            {"body": b'{"endpoints":1}', "kind": "agent.recon_completed"},
        )
        session.commit()

        corrected = recon_for(("GET", "/portal/login.aspx"))
        corrected.base_url = f"https://{TARGET_HOST}/portal/"
        controller = controller_with(
            session, MissionId(mission.id), executor=RecordingExecutor(), recon=corrected
        )
        controller.run_cycle(controller.start_run())

    assert corrected.calls == 1, "the corrected entry URL was still not visited"


def test_turning_on_empty_body_probing_makes_the_sweep_due(engine: Engine) -> None:
    """The inventory has not changed, so no endpoint is new -- but every mutating one
    has never been asked anything, and making that decision wait a day is the same
    restraint costing more than it saves as the cadence rules above."""
    factory = session_factory(engine)
    with factory() as session:
        engagement_id = seed_engagement(session)
        mission = seed_mission(session, engagement_id)
        session.commit()

        surface = (("GET", "/api/alpha"), ("POST", "/api/setThing"))
        controller = controller_with(
            session,
            MissionId(mission.id),
            executor=RecordingExecutor(),
            recon=recon_for(*surface),
            prober=StubProber(),
        )
        controller.run_cycle(controller.start_run())

        widened = StubProber()
        controller = controller_with(
            session,
            MissionId(mission.id),
            executor=RecordingExecutor(),
            recon=recon_for(*surface),
            prober=widened,
            probe_mutating=True,
            now=NOW + timedelta(hours=2),
        )
        controller.run_cycle(controller.start_run())

    assert widened.plans, "the mutating endpoints were deferred for a day"
    assert any(spec.path == "/api/setThing" for plan in widened.plans for spec in plan)


def test_narrowing_the_plan_does_not_make_the_sweep_due(engine: Engine) -> None:
    """Going back to read-only asks nothing that has not been asked, so it waits."""
    factory = session_factory(engine)
    with factory() as session:
        engagement_id = seed_engagement(session)
        mission = seed_mission(session, engagement_id)
        session.commit()

        surface = (("GET", "/api/alpha"), ("POST", "/api/setThing"))
        controller = controller_with(
            session,
            MissionId(mission.id),
            executor=RecordingExecutor(),
            recon=recon_for(*surface),
            prober=StubProber(),
            probe_mutating=True,
        )
        controller.run_cycle(controller.start_run())

        narrowed = StubProber()
        controller = controller_with(
            session,
            MissionId(mission.id),
            executor=RecordingExecutor(),
            recon=recon_for(*surface),
            prober=narrowed,
            now=NOW + timedelta(hours=2),
        )
        controller.run_cycle(controller.start_run())

    assert narrowed.plans == []


def test_a_sweep_recorded_before_this_was_tracked_does_not_block_widening(
    engine: Engine,
) -> None:
    """Every record predating a change predates it. A caution that reads a missing
    field as "already asked" makes the rule unreachable for exactly the targets it
    exists for -- which is the second time in a day that shape of mistake appeared."""
    factory = session_factory(engine)
    with factory() as session:
        engagement_id = seed_engagement(session)
        mission = seed_mission(session, engagement_id)
        session.commit()

        surface = (("GET", "/api/alpha"), ("POST", "/api/setThing"))
        controller = controller_with(
            session,
            MissionId(mission.id),
            executor=RecordingExecutor(),
            recon=recon_for(*surface),
            prober=StubProber(),
        )
        controller.run_cycle(controller.start_run())

        # A sweep record as an older release wrote it: counts, and nothing about scope.
        session.execute(
            text("update audit_events set payload = :body where event_type = :kind"),
            {"body": b'{"probed": 1, "withheld": 1}', "kind": "agent.sweep_completed"},
        )
        session.commit()

        widened = StubProber()
        controller = controller_with(
            session,
            MissionId(mission.id),
            executor=RecordingExecutor(),
            recon=recon_for(*surface),
            prober=widened,
            probe_mutating=True,
            now=NOW + timedelta(hours=2),
        )
        controller.run_cycle(controller.start_run())

    assert widened.plans, "an old record blocked the decision it knew nothing about"


def test_the_budget_sees_a_sweep_while_it_is_still_running(engine: Engine) -> None:
    """A paced sweep of two hundred endpoints runs for an hour and a half. The ledger
    used to be written from the batch the sweep returns at the end, so for all of that
    time it said nothing had been spent -- the budget could not see work in flight, and
    nothing outside could tell a long sweep from a stuck one.

    I could not tell either, and told the operator the agent had hung when it was
    working."""
    factory = session_factory(engine)
    with factory() as session:
        engagement_id = seed_engagement(session)
        mission = seed_mission(session, engagement_id)
        session.commit()

        seen_mid_sweep: list[int] = []

        class Slow(StubProber):
            def probe(
                self,
                endpoints: Sequence[EndpointSpec],
                *,
                at: datetime,
                on_request: Callable[[datetime], None] | None = None,
            ) -> ProbeOutcome:
                self.plans.append(tuple(endpoints))
                assert on_request is not None
                for index in range(3):
                    on_request(at + timedelta(seconds=20 * index))
                    # What the ledger holds part-way through, which used to be nothing.
                    seen_mid_sweep.append(
                        session.execute(
                            text("select coalesce(sum(request_count), 0) "
                                 "from budget_ledger where window_kind = 'minute'")
                        ).scalar_one()
                    )
                return ProbeOutcome(verdicts=(), sent_at=())

        controller = controller_with(
            session,
            MissionId(mission.id),
            executor=RecordingExecutor(),
            recon=recon_for(("GET", "/api/alpha")),
            prober=Slow(),
        )
        controller.run_cycle(controller.start_run())

    assert seen_mid_sweep == [1, 2, 3], (
        f"the ledger did not follow the sweep: {seen_mid_sweep}"
    )


def test_a_request_is_not_charged_twice(engine: Engine) -> None:
    """The callback charges as it goes and the returned batch is charged afterwards.
    Double-counting would make the budget refuse work that was never done."""
    factory = session_factory(engine)
    with factory() as session:
        engagement_id = seed_engagement(session)
        mission = seed_mission(session, engagement_id)
        session.commit()

        prober = StubProber(requests_sent=4)
        controller = controller_with(
            session,
            MissionId(mission.id),
            executor=RecordingExecutor(),
            recon=recon_for(("GET", "/api/alpha")),
            prober=prober,
        )
        controller.run_cycle(controller.start_run())

        charged = session.execute(
            text("select coalesce(sum(request_count), 0) from budget_ledger "
                 "where window_kind = 'minute'")
        ).scalar_one()

    assert charged == 4


def test_a_sweep_the_budget_cut_short_continues_next_cycle(engine: Engine) -> None:
    """The largest target holds 397 probeable endpoints and its last completed sweep
    reached 63. The other 334 were withheld for budget -- not asked, and not new, so
    neither of the other two rules reaches them -- and the cadence then held them for
    twenty-four hours, to be refused again."""
    factory = session_factory(engine)
    with factory() as session:
        engagement_id = seed_engagement(session)
        # The sweep's headroom comes from the hour, day and total windows; the
        # per-minute rate governs how fast it sends, not how much it may plan.
        mission = seed_mission(
            session, engagement_id, budget=MissionBudget(requests_per_hour=2)
        )
        session.commit()

        surface = tuple(("GET", f"/api/thing{index}") for index in range(6))
        first = StubProber()
        controller = controller_with(
            session,
            MissionId(mission.id),
            executor=RecordingExecutor(),
            recon=recon_for(*surface),
            prober=first,
        )
        controller.run_cycle(controller.start_run())
        assert first.plans, "the first sweep did not run"
        assert len(first.plans[0]) < len(surface), "the budget did not cut the plan short"

        later = StubProber()
        controller = controller_with(
            session,
            MissionId(mission.id),
            executor=RecordingExecutor(),
            recon=recon_for(*surface),
            prober=later,
            now=NOW + timedelta(hours=2),
        )
        controller.run_cycle(controller.start_run())

    assert later.plans, "the endpoints the budget refused waited a day to be refused again"


def test_a_sweep_that_finished_its_plan_still_waits(engine: Engine) -> None:
    """The restraint being relaxed is about re-asking, and that stays."""
    factory = session_factory(engine)
    with factory() as session:
        engagement_id = seed_engagement(session)
        mission = seed_mission(session, engagement_id)
        session.commit()

        controller = controller_with(
            session,
            MissionId(mission.id),
            executor=RecordingExecutor(),
            recon=recon_for(("GET", "/api/alpha")),
            prober=StubProber(),
        )
        controller.run_cycle(controller.start_run())

        later = StubProber()
        controller = controller_with(
            session,
            MissionId(mission.id),
            executor=RecordingExecutor(),
            recon=recon_for(("GET", "/api/alpha")),
            prober=later,
            now=NOW + timedelta(hours=2),
        )
        controller.run_cycle(controller.start_run())

    assert later.plans == []
