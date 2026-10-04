"""Tests for reconnaissance and candidate recording inside the mission cycle.

These close the loop: a bundle is read, endpoints are recovered and classified, and a
machine-judged observation becomes work the controller will pick up on a later cycle.
"""

from __future__ import annotations

from collections.abc import Generator
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from types import SimpleNamespace

import pytest
from sqlalchemy import Engine

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
from vuln_proof_claw.agent.controller import MissionController
from vuln_proof_claw.agent.differential import OracleRule, OracleVerdict
from vuln_proof_claw.agent.endpoints import EndpointClassification, classify_all
from vuln_proof_claw.agent.planner import DeterministicPlanner
from vuln_proof_claw.domain.autonomous import MissionCadence
from vuln_proof_claw.domain.enums import LeadStatus
from vuln_proof_claw.domain.identifiers import MissionId
from vuln_proof_claw.persistence.autonomous_repositories import (
    EndpointRepository,
    LeadRepository,
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

    def discover(self, *, at: datetime) -> SimpleNamespace:
        self.calls += 1
        if self.explode:
            raise RuntimeError("bundle unreachable")
        return SimpleNamespace(
            base_url=f"https://{TARGET_HOST}/",
            classifications=self.classifications,
            surface_digest="d" * 64,
        )


def recon_for(*paths: tuple[str, str]) -> StubRecon:
    return StubRecon(classifications=classify_all(paths))


def controller_with(
    session: object,
    mission_id: MissionId,
    *,
    executor: RecordingExecutor,
    recon: StubRecon | None = None,
) -> MissionController:
    return MissionController(
        session,  # type: ignore[arg-type]
        mission_id,
        planner=DeterministicPlanner(),
        executor=executor,
        clock=frozen_clock(),  # type: ignore[arg-type]
        reconnaissance=recon,  # type: ignore[arg-type]
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
