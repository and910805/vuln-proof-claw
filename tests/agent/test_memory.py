"""Tests for persistent research memory."""

from __future__ import annotations

from collections.abc import Generator
from datetime import timedelta
from pathlib import Path

import pytest
from sqlalchemy import Engine

from tests.agent.support import (
    NOW,
    TARGET_HOST,
    build_engine,
    seed_engagement,
    seed_lead,
    seed_mission,
    seed_surface,
    session_factory,
)
from vuln_proof_claw.agent.memory import ResearchMemory
from vuln_proof_claw.agent.surface import SurfaceTracker
from vuln_proof_claw.domain.autonomous import Observation
from vuln_proof_claw.domain.enums import LeadStatus, ObservationKind
from vuln_proof_claw.domain.identifiers import MissionId
from vuln_proof_claw.persistence.autonomous_repositories import ObservationRepository

DIGEST = "a" * 64
LATER = NOW + timedelta(hours=1)


@pytest.fixture
def engine(tmp_path: Path) -> Generator[Engine, None, None]:
    yield from build_engine(tmp_path / "memory.db")


def test_a_never_attempted_lead_always_counts_as_having_new_evidence(engine: Engine) -> None:
    factory = session_factory(engine)
    with factory.begin() as session:
        engagement_id = seed_engagement(session)
        mission = seed_mission(session, engagement_id)
        lead = seed_lead(session, engagement_id, MissionId(mission.id))

        memory = ResearchMemory(session, engagement_id)

        assert memory.has_new_evidence_since(lead)


def test_no_new_evidence_is_reported_when_nothing_happened_since_the_attempt(
    engine: Engine,
) -> None:
    factory = session_factory(engine)
    with factory.begin() as session:
        engagement_id = seed_engagement(session)
        mission = seed_mission(session, engagement_id)
        lead = seed_lead(
            session,
            engagement_id,
            MissionId(mission.id),
            attempt_count=1,
            failure_count=1,
            last_attempt_at=NOW,
        )

        memory = ResearchMemory(session, engagement_id)

        assert not memory.has_new_evidence_since(lead)


def test_a_later_observation_counts_as_new_evidence(engine: Engine) -> None:
    factory = session_factory(engine)
    with factory.begin() as session:
        engagement_id = seed_engagement(session)
        mission = seed_mission(session, engagement_id)
        lead = seed_lead(
            session,
            engagement_id,
            MissionId(mission.id),
            attempt_count=1,
            last_attempt_at=NOW,
        )
        ObservationRepository(session).add(
            Observation(
                engagement_id=engagement_id,
                kind=ObservationKind.HTTP_RESPONSE,
                subject=TARGET_HOST,
                digest=DIGEST,
                summary="status changed from 403 to 200",
                observed_at=LATER,
            )
        )

        memory = ResearchMemory(session, engagement_id)

        assert memory.has_new_evidence_since(lead)


def test_a_surface_change_counts_as_new_evidence(engine: Engine) -> None:
    factory = session_factory(engine)
    with factory.begin() as session:
        engagement_id = seed_engagement(session)
        mission = seed_mission(session, engagement_id)
        lead = seed_lead(
            session,
            engagement_id,
            MissionId(mission.id),
            attempt_count=1,
            last_attempt_at=NOW,
        )
        seed_surface(session, engagement_id, at=NOW)
        tracker = SurfaceTracker(session, engagement_id)
        tracker.capture(at=NOW)
        seed_surface(session, engagement_id, at=LATER, path="/invoices")
        tracker.capture(at=LATER)

        memory = ResearchMemory(session, engagement_id)

        assert memory.has_new_evidence_since(lead)


def test_recall_reports_whether_a_retry_is_justified(engine: Engine) -> None:
    factory = session_factory(engine)
    with factory.begin() as session:
        engagement_id = seed_engagement(session)
        mission = seed_mission(session, engagement_id)
        failed = seed_lead(
            session,
            engagement_id,
            MissionId(mission.id),
            attempt_count=1,
            failure_count=1,
            last_attempt_at=NOW,
        )

        memory = ResearchMemory(session, engagement_id)
        recall = memory.recall(failed)

    assert recall.failure_count == 1
    assert not recall.has_new_evidence
    assert not recall.retry_justified


def test_failed_hypotheses_are_recalled_so_they_are_not_reproposed(engine: Engine) -> None:
    factory = session_factory(engine)
    with factory.begin() as session:
        engagement_id = seed_engagement(session)
        mission = seed_mission(session, engagement_id)
        seed_lead(
            session,
            engagement_id,
            MissionId(mission.id),
            status=LeadStatus.REJECTED,
            dedupe_key="rejected-one",
        )
        seed_lead(
            session,
            engagement_id,
            MissionId(mission.id),
            hypothesis="a different idea",
            dedupe_key="open-one",
        )

        memory = ResearchMemory(session, engagement_id)
        failed = memory.failed_hypotheses(MissionId(mission.id))

    assert len(failed) == 1
    assert failed[0].status is LeadStatus.REJECTED


def test_surface_counts_reflect_the_inventory(engine: Engine) -> None:
    factory = session_factory(engine)
    with factory.begin() as session:
        engagement_id = seed_engagement(session)
        seed_surface(session, engagement_id)
        seed_surface(session, engagement_id, path="/invoices")

        counts = ResearchMemory(session, engagement_id).surface_counts()

    assert counts.assets == 1
    assert counts.endpoints == 2
