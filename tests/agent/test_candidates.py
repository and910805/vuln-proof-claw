"""Tests for turning verdicts and recovered endpoints into research objects."""

from __future__ import annotations

from collections.abc import Generator
from datetime import UTC, datetime
from pathlib import Path

import pytest
from sqlalchemy import Engine

from tests.agent.support import build_engine, seed_engagement, seed_mission, session_factory
from vuln_proof_claw.agent.candidates import (
    promote_candidate,
    record_endpoints,
    record_verdicts,
    verdict_digest,
)
from vuln_proof_claw.agent.differential import OracleRule, OracleVerdict, ProbeResult
from vuln_proof_claw.agent.endpoints import classify_all
from vuln_proof_claw.domain.enums import LeadStatus
from vuln_proof_claw.domain.identifiers import MissionId
from vuln_proof_claw.persistence.autonomous_repositories import (
    CandidateRepository,
    EndpointRepository,
    LeadRepository,
)

NOW = datetime(2026, 10, 5, 12, 0, tzinfo=UTC)
TARGET = "https://api.example.com:443/api/getCompanyDisplay"
BASE = "https://api.example.com/"

INVENTORY: tuple[tuple[str, str], ...] = (
    ("GET", "/api/getCompanyDisplay"),
    ("POST", "/api/setDeviceMessage"),
    ("POST", "/api/setDeviceSecureWipe"),
    ("POST", "/api/deleteAccount"),
)


@pytest.fixture
def engine(tmp_path: Path) -> Generator[Engine, None, None]:
    yield from build_engine(tmp_path / "candidates.db")


def triggered(
    rule: OracleRule = OracleRule.MISSING_AUTHENTICATION, target: str = TARGET
) -> OracleVerdict:
    return OracleVerdict(
        rule,
        triggered=True,
        target=target,
        reason="an unauthenticated request received 200 with a 94-byte response",
        probes=(
            ProbeResult(
                identity="anonymous",
                method="GET",
                target=target,
                status_code=200,
                body_digest="a" * 64,
                body_size=94,
            ),
        ),
    )


def clear(rule: OracleRule = OracleRule.MISSING_AUTHENTICATION) -> OracleVerdict:
    return OracleVerdict(rule, triggered=False, target=TARGET, reason="correctly refused")


def test_only_triggered_verdicts_become_candidates(engine: Engine) -> None:
    factory = session_factory(engine)
    with factory.begin() as session:
        engagement_id = seed_engagement(session)

        result = record_verdicts(
            session, engagement_id, [triggered(), clear()], at=NOW
        )

    assert result.total == 1
    assert result.created[0].category == "缺乏身分鑑別"
    assert result.created[0].target == TARGET


def test_the_same_observation_is_not_recorded_twice(engine: Engine) -> None:
    """A cycle that re-runs must not accumulate duplicates of the same finding."""
    factory = session_factory(engine)
    with factory.begin() as session:
        engagement_id = seed_engagement(session)

        first = record_verdicts(session, engagement_id, [triggered()], at=NOW)
        second = record_verdicts(session, engagement_id, [triggered()], at=NOW)

    assert first.total == 1
    assert second.total == 0
    assert second.duplicates == 1


def test_the_digest_ignores_volatile_detail() -> None:
    """Byte counts shift between runs; the identity of the observation does not."""
    stable = verdict_digest(triggered())
    reworded = OracleVerdict(
        OracleRule.MISSING_AUTHENTICATION,
        triggered=True,
        target=TARGET,
        reason="an unauthenticated request received 200 with a 97-byte response",
    )

    assert verdict_digest(reworded) == stable


def test_different_rules_on_one_target_are_distinct_candidates() -> None:
    assert verdict_digest(triggered(OracleRule.MISSING_AUTHENTICATION)) != verdict_digest(
        triggered(OracleRule.HORIZONTAL_PRIVILEGE)
    )


def test_a_candidate_becomes_a_schedulable_lead(engine: Engine) -> None:
    factory = session_factory(engine)
    with factory.begin() as session:
        engagement_id = seed_engagement(session)
        mission = seed_mission(session, engagement_id)
        verdict = triggered()
        candidate = record_verdicts(session, engagement_id, [verdict], at=NOW).created[0]

        lead = promote_candidate(
            session, candidate, mission_id=MissionId(mission.id), verdict=verdict, at=NOW
        )

    assert lead is not None
    assert lead.status is LeadStatus.NEW
    assert lead.next_action == TARGET
    assert "尚未經研究員驗證" in lead.hypothesis
    assert "differential-oracle" in lead.origin


def test_a_lead_is_linked_back_to_its_candidate(engine: Engine) -> None:
    factory = session_factory(engine)
    with factory.begin() as session:
        engagement_id = seed_engagement(session)
        mission = seed_mission(session, engagement_id)
        verdict = triggered()
        candidate = record_verdicts(session, engagement_id, [verdict], at=NOW).created[0]
        promote_candidate(
            session, candidate, mission_id=MissionId(mission.id), verdict=verdict, at=NOW
        )

        untriaged = CandidateRepository(session).list_untriaged(engagement_id)

    assert untriaged == ()


def test_promoting_the_same_hypothesis_twice_yields_one_lead(engine: Engine) -> None:
    factory = session_factory(engine)
    with factory.begin() as session:
        engagement_id = seed_engagement(session)
        mission = seed_mission(session, engagement_id)
        verdict = triggered()
        candidate = record_verdicts(session, engagement_id, [verdict], at=NOW).created[0]

        first = promote_candidate(
            session, candidate, mission_id=MissionId(mission.id), verdict=verdict, at=NOW
        )
        second = promote_candidate(
            session, candidate, mission_id=MissionId(mission.id), verdict=verdict, at=NOW
        )

        leads = LeadRepository(session).list_by_status(
            MissionId(mission.id), (LeadStatus.NEW,)
        )

    assert first is not None
    assert second is None
    assert len(leads) == 1


def test_a_stronger_rule_produces_a_higher_priority_lead(engine: Engine) -> None:
    """Confidence is a property of the rule, not a judgement about the target."""
    factory = session_factory(engine)
    with factory.begin() as session:
        engagement_id = seed_engagement(session)
        mission = seed_mission(session, engagement_id)

        weak_verdict = triggered(OracleRule.DENIAL_INCONSISTENCY, "https://a.example.com:443/x")
        strong_verdict = triggered(
            OracleRule.HORIZONTAL_PRIVILEGE, "https://a.example.com:443/y"
        )
        recorded = record_verdicts(
            session, engagement_id, [weak_verdict, strong_verdict], at=NOW
        )
        weak = promote_candidate(
            session,
            recorded.created[0],
            mission_id=MissionId(mission.id),
            verdict=weak_verdict,
            at=NOW,
        )
        strong = promote_candidate(
            session,
            recorded.created[1],
            mission_id=MissionId(mission.id),
            verdict=strong_verdict,
            at=NOW,
        )

    assert weak is not None
    assert strong is not None
    assert strong.priority > weak.priority
    assert strong.confidence > weak.confidence


def test_recovered_endpoints_are_stored_including_the_dangerous_ones(
    engine: Engine,
) -> None:
    """Destructive endpoints are never called, but an operator must still see them."""
    factory = session_factory(engine)
    with factory.begin() as session:
        engagement_id = seed_engagement(session, allowed_hostnames=("api.example.com",))

        stored, held = record_endpoints(
            session, engagement_id, BASE, classify_all(INVENTORY), at=NOW
        )
        endpoints = EndpointRepository(session).list_for_engagement(engagement_id)

    assert stored == len(INVENTORY)
    assert held == 2
    paths = {item.entity.path for item in endpoints}
    assert "/api/setDeviceSecureWipe" in paths
    assert "/api/deleteAccount" in paths


def test_endpoint_risk_is_recorded_in_the_source_field(engine: Engine) -> None:
    factory = session_factory(engine)
    with factory.begin() as session:
        engagement_id = seed_engagement(session, allowed_hostnames=("api.example.com",))
        record_endpoints(session, engagement_id, BASE, classify_all(INVENTORY), at=NOW)

        endpoints = EndpointRepository(session).list_for_engagement(engagement_id)
        by_path = {item.entity.path: item.entity.source for item in endpoints}

    assert by_path["/api/setDeviceSecureWipe"] == "jsdiscovery:destructive"
    assert by_path["/api/getCompanyDisplay"] == "jsdiscovery:read"


def test_re_running_reconnaissance_does_not_duplicate_endpoints(engine: Engine) -> None:
    factory = session_factory(engine)
    with factory.begin() as session:
        engagement_id = seed_engagement(session, allowed_hostnames=("api.example.com",))
        record_endpoints(session, engagement_id, BASE, classify_all(INVENTORY), at=NOW)
        record_endpoints(session, engagement_id, BASE, classify_all(INVENTORY), at=NOW)

        count = EndpointRepository(session).count(engagement_id)

    assert count == len(INVENTORY)
