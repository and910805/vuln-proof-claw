"""Tests for autonomous mission and knowledge-base repositories."""

from __future__ import annotations

from collections.abc import Generator
from dataclasses import replace
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
from vuln_proof_claw.domain.autonomous import (
    AgentCycle,
    Asset,
    Candidate,
    MissionBudget,
    MissionCadence,
    MissionRun,
    Observation,
)
from vuln_proof_claw.domain.enums import (
    AssetKind,
    CandidateSource,
    CycleState,
    LeadStatus,
    MissionRunState,
    MissionState,
    ObservationKind,
)
from vuln_proof_claw.domain.identifiers import MissionId
from vuln_proof_claw.persistence.autonomous_repositories import (
    AgentCycleRepository,
    AssetRepository,
    CandidateRepository,
    EndpointRepository,
    LeadRepository,
    MissionRepository,
    MissionRunRepository,
    ObservationRepository,
)
from vuln_proof_claw.persistence.repositories import ConcurrentUpdateError

DIGEST = "b" * 64
LATER = NOW + timedelta(hours=1)


@pytest.fixture
def engine(tmp_path: Path) -> Generator[Engine, None, None]:
    yield from build_engine(tmp_path / "autonomous.db")


def test_mission_round_trips_cadence_and_budget(engine: Engine) -> None:
    factory = session_factory(engine)
    with factory.begin() as session:
        engagement_id = seed_engagement(session)
        cadence = MissionCadence(cycle_interval_seconds=120, deep_recon_seconds=43_200)
        budget = MissionBudget(requests_per_minute_per_domain=3, llm_tokens_per_lead=1_234)
        mission = seed_mission(session, engagement_id, cadence=cadence, budget=budget)

        stored = MissionRepository(session).get(MissionId(mission.id))

    assert stored is not None
    assert stored.entity.cadence == cadence
    assert stored.entity.budget == budget


def test_mission_is_findable_by_name_and_state(engine: Engine) -> None:
    factory = session_factory(engine)
    with factory.begin() as session:
        engagement_id = seed_engagement(session)
        mission = seed_mission(session, engagement_id)

        by_name = MissionRepository(session).find_by_name(engagement_id, mission.name)
        by_state = MissionRepository(session).list_by_state(MissionState.RUNNING)

    assert by_name is not None
    assert by_name.entity.id == mission.id
    assert [item.entity.id for item in by_state] == [mission.id]


def test_mission_save_rejects_a_stale_version(engine: Engine) -> None:
    factory = session_factory(engine)
    with factory.begin() as session:
        engagement_id = seed_engagement(session)
        mission = seed_mission(session, engagement_id)
        repository = MissionRepository(session)
        repository.save(
            replace(mission, state=MissionState.PAUSED, updated_at=LATER), expected_version=1
        )

        with pytest.raises(ConcurrentUpdateError):
            repository.save(
                replace(mission, state=MissionState.STOPPED, updated_at=LATER),
                expected_version=1,
            )


def test_mission_run_tracks_heartbeat_and_completion(engine: Engine) -> None:
    factory = session_factory(engine)
    with factory.begin() as session:
        engagement_id = seed_engagement(session)
        mission = seed_mission(session, engagement_id)
        repository = MissionRunRepository(session)
        run = MissionRun(
            engagement_id=engagement_id,
            mission_id=MissionId(mission.id),
            started_at=NOW,
            heartbeat_at=NOW,
        )
        repository.add(run)

        running = repository.list_running()
        repository.save(
            replace(run, state=MissionRunState.COMPLETED, ended_at=LATER, heartbeat_at=LATER),
            expected_version=1,
        )
        after = repository.list_running()

    assert [item.entity.id for item in running] == [run.id]
    assert after == ()


def test_agent_cycles_are_unique_per_index_and_listed_newest_first(engine: Engine) -> None:
    factory = session_factory(engine)
    with factory.begin() as session:
        engagement_id = seed_engagement(session)
        mission = seed_mission(session, engagement_id)
        run = MissionRun(
            engagement_id=engagement_id,
            mission_id=MissionId(mission.id),
            started_at=NOW,
            heartbeat_at=NOW,
        )
        MissionRunRepository(session).add(run)
        repository = AgentCycleRepository(session)
        for index in range(3):
            repository.add(
                AgentCycle(
                    engagement_id=engagement_id,
                    mission_run_id=run.id,
                    index=index,
                    state=CycleState.COMPLETED,
                    started_at=NOW,
                    ended_at=LATER,
                )
            )

        cycles = repository.list_for_run(run.id)

    assert [item.entity.index for item in cycles] == [2, 1, 0]


def test_lead_round_trips_every_investigation_field(engine: Engine) -> None:
    factory = session_factory(engine)
    with factory.begin() as session:
        engagement_id = seed_engagement(session)
        mission = seed_mission(session, engagement_id)
        lead = seed_lead(
            session,
            engagement_id,
            MissionId(mission.id),
            origin=("openapi-analysis", "differential-testing"),
            confidence=0.63,
            priority=78,
            attempt_count=3,
            failure_count=1,
            last_attempt_at=NOW,
            next_attempt_at=LATER,
            last_reasoning_summary="compared two identities",
            dedupe_key="abc123",
        )

        stored = LeadRepository(session).find_by_dedupe_key(MissionId(mission.id), "abc123")

    assert stored is not None
    assert stored.entity.id == lead.id
    assert stored.entity.origin == ("openapi-analysis", "differential-testing")
    assert stored.entity.confidence == pytest.approx(0.63)
    assert stored.entity.attempt_count == 3
    assert stored.entity.next_attempt_at == LATER


def test_due_leads_exclude_those_still_in_cooldown(engine: Engine) -> None:
    factory = session_factory(engine)
    with factory.begin() as session:
        engagement_id = seed_engagement(session)
        mission = seed_mission(session, engagement_id)
        ready = seed_lead(session, engagement_id, MissionId(mission.id), dedupe_key="ready")
        seed_lead(
            session,
            engagement_id,
            MissionId(mission.id),
            hypothesis="cooling down",
            dedupe_key="cooling",
            status=LeadStatus.WAITING,
            attempt_count=1,
            failure_count=1,
            last_attempt_at=NOW,
            next_attempt_at=LATER,
        )

        due = LeadRepository(session).list_due(
            MissionId(mission.id),
            (LeadStatus.NEW, LeadStatus.QUEUED, LeadStatus.WAITING),
            at=NOW,
        )

    assert [item.entity.id for item in due] == [ready.id]


def test_leads_are_counted_by_status(engine: Engine) -> None:
    factory = session_factory(engine)
    with factory.begin() as session:
        engagement_id = seed_engagement(session)
        mission = seed_mission(session, engagement_id)
        seed_lead(session, engagement_id, MissionId(mission.id), dedupe_key="a")
        seed_lead(
            session,
            engagement_id,
            MissionId(mission.id),
            hypothesis="second",
            dedupe_key="b",
            status=LeadStatus.REJECTED,
        )

        counts = LeadRepository(session).count_by_status(MissionId(mission.id))

    assert counts[LeadStatus.NEW] == 1
    assert counts[LeadStatus.REJECTED] == 1


def test_observing_a_known_asset_merges_rather_than_duplicating(engine: Engine) -> None:
    factory = session_factory(engine)
    with factory.begin() as session:
        engagement_id = seed_engagement(session)
        repository = AssetRepository(session)
        repository.observe(
            Asset(
                engagement_id=engagement_id,
                kind=AssetKind.HOSTNAME,
                identifier=TARGET_HOST,
                technologies=("nginx",),
                first_seen_at=NOW,
                last_seen_at=NOW,
            )
        )
        merged = repository.observe(
            Asset(
                engagement_id=engagement_id,
                kind=AssetKind.HOSTNAME,
                identifier=TARGET_HOST,
                technologies=("fastapi",),
                first_seen_at=LATER,
                last_seen_at=LATER,
            )
        )

    assert repository.count(engagement_id) == 1
    assert merged.entity.technologies == ("fastapi", "nginx")
    assert merged.entity.last_seen_at == LATER
    assert merged.entity.first_seen_at == NOW


def test_observing_a_known_endpoint_merges_parameters(engine: Engine) -> None:
    factory = session_factory(engine)
    with factory.begin() as session:
        engagement_id = seed_engagement(session)
        _, endpoint = seed_surface(session, engagement_id)
        repository = EndpointRepository(session)
        merged = repository.observe(
            replace(
                endpoint,
                parameters=("page", "limit"),
                requires_authentication=True,
                last_seen_at=LATER,
            )
        )

    assert repository.count(engagement_id) == 1
    assert merged.entity.parameters == ("limit", "page")
    assert merged.entity.requires_authentication is True


def test_observations_are_queryable_by_time_and_subject(engine: Engine) -> None:
    factory = session_factory(engine)
    with factory.begin() as session:
        engagement_id = seed_engagement(session)
        repository = ObservationRepository(session)
        repository.add(
            Observation(
                engagement_id=engagement_id,
                kind=ObservationKind.HTTP_RESPONSE,
                subject=TARGET_HOST,
                digest=DIGEST,
                summary="status 200",
                observed_at=LATER,
            )
        )

        recent = repository.list_since(engagement_id, since=NOW)
        none_yet = repository.list_since(engagement_id, since=LATER)
        by_subject = repository.list_for_subject(engagement_id, TARGET_HOST)

    assert len(recent) == 1
    assert none_yet == ()
    assert len(by_subject) == 1


def test_candidates_deduplicate_on_raw_digest_and_attach_to_leads(engine: Engine) -> None:
    factory = session_factory(engine)
    with factory.begin() as session:
        engagement_id = seed_engagement(session)
        mission = seed_mission(session, engagement_id)
        lead = seed_lead(session, engagement_id, MissionId(mission.id))
        repository = CandidateRepository(session)
        candidate = Candidate(
            engagement_id=engagement_id,
            source=CandidateSource.SCANNER,
            tool_name="nuclei",
            title="exposed administrative panel",
            category="exposure",
            target=f"https://{TARGET_HOST}/admin",
            raw_digest=DIGEST,
            created_at=NOW,
        )
        repository.add(candidate)

        found = repository.find_by_digest(engagement_id, DIGEST)
        untriaged = repository.list_untriaged(engagement_id)
        repository.attach_lead(candidate.id, lead.id)
        remaining = repository.list_untriaged(engagement_id)

    assert found is not None
    assert len(untriaged) == 1
    assert remaining == ()
