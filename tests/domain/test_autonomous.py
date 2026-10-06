"""Tests for autonomous mission domain invariants."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest

from vuln_proof_claw.domain.autonomous import (
    MAXIMUM_AUTONOMOUS_RISK,
    AgentCycle,
    Asset,
    Candidate,
    ChangeEvent,
    Endpoint,
    Lead,
    Mission,
    MissionBudget,
    MissionCadence,
    MissionRun,
    Observation,
    SurfaceSnapshot,
)
from vuln_proof_claw.domain.enums import (
    AssetKind,
    CandidateSource,
    ChangeKind,
    CycleState,
    LeadStatus,
    MissionRunState,
    MissionState,
    ObservationKind,
    RiskLevel,
)
from vuln_proof_claw.domain.errors import DomainValidationError
from vuln_proof_claw.domain.identifiers import (
    EvidenceId,
    new_asset_id,
    new_engagement_id,
    new_mission_id,
    new_mission_run_id,
    new_surface_snapshot_id,
)

NOW = datetime(2026, 10, 4, 12, 0, tzinfo=UTC)
DIGEST = "a" * 64
ENGAGEMENT = new_engagement_id()
MISSION = new_mission_id()
EVIDENCE = (EvidenceId("11111111-1111-7111-8111-111111111111"),)


def make_mission(**overrides: object) -> Mission:
    defaults: dict[str, object] = {
        "engagement_id": ENGAGEMENT,
        "name": "continuous-research",
        "created_at": NOW,
        "updated_at": NOW,
    }
    defaults.update(overrides)
    return Mission(**defaults)  # type: ignore[arg-type]


def make_lead(**overrides: object) -> Lead:
    defaults: dict[str, object] = {
        "engagement_id": ENGAGEMENT,
        "mission_id": MISSION,
        "title": "Possible authorization weakness",
        "hypothesis": "Ownership may not be enforced",
        "category": "authorization",
        "created_at": NOW,
        "updated_at": NOW,
    }
    defaults.update(overrides)
    return Lead(**defaults)  # type: ignore[arg-type]


@pytest.mark.parametrize("risk", [RiskLevel.L2, RiskLevel.L3, RiskLevel.L4])
def test_a_mission_can_never_raise_its_autonomous_risk_ceiling(risk: RiskLevel) -> None:
    with pytest.raises(DomainValidationError):
        make_mission(maximum_autonomous_risk=risk)


def test_the_autonomous_ceiling_is_l1() -> None:
    assert MAXIMUM_AUTONOMOUS_RISK is RiskLevel.L1
    assert make_mission().maximum_autonomous_risk is RiskLevel.L1


def test_a_mission_permits_cycles_only_while_running_and_unexpired() -> None:
    running = make_mission(state=MissionState.RUNNING)
    paused = make_mission(state=MissionState.PAUSED)
    killed = make_mission(state=MissionState.RUNNING, kill_switch_engaged=True)
    expiring = make_mission(state=MissionState.RUNNING, expires_at=NOW + timedelta(hours=1))

    assert running.permits_cycle(at=NOW)
    assert not paused.permits_cycle(at=NOW)
    assert not killed.permits_cycle(at=NOW)
    assert not expiring.permits_cycle(at=NOW + timedelta(hours=2))


def test_mission_expiry_must_follow_creation() -> None:
    with pytest.raises(DomainValidationError):
        make_mission(expires_at=NOW - timedelta(hours=1))


@pytest.mark.parametrize(
    "overrides",
    [
        {"cycle_interval_seconds": 1},
        {"http_inventory_seconds": 0},
        {"deep_recon_seconds": 10_000_000},
    ],
)
def test_cadence_intervals_are_bounded(overrides: dict[str, int]) -> None:
    with pytest.raises(DomainValidationError):
        MissionCadence(**overrides)


def test_budget_ceilings_must_be_internally_consistent() -> None:
    with pytest.raises(DomainValidationError):
        MissionBudget(requests_per_hour=10_000, requests_per_day=100)
    with pytest.raises(DomainValidationError):
        MissionBudget(requests_per_day=100_000, total_requests=1_000)


def test_a_verified_lead_requires_evidence() -> None:
    with pytest.raises(DomainValidationError):
        make_lead(status=LeadStatus.VERIFIED)

    assert make_lead(status=LeadStatus.VERIFIED, evidence_ids=EVIDENCE).evidence_ids == EVIDENCE


def test_a_lead_awaiting_approval_must_record_why() -> None:
    with pytest.raises(DomainValidationError):
        make_lead(status=LeadStatus.NEEDS_APPROVAL)


def test_lead_counters_and_confidence_are_bounded() -> None:
    with pytest.raises(DomainValidationError):
        make_lead(confidence=1.5)
    with pytest.raises(DomainValidationError):
        make_lead(priority=101)
    with pytest.raises(DomainValidationError):
        make_lead(attempt_count=1, failure_count=2, last_attempt_at=NOW)
    with pytest.raises(DomainValidationError):
        make_lead(attempt_count=1)


def test_lead_status_classification() -> None:
    assert LeadStatus.VERIFIED.terminal
    assert LeadStatus.QUEUED.eligible_for_scheduling
    assert LeadStatus.STALE.reawakenable
    assert not LeadStatus.INVESTIGATING.eligible_for_scheduling


def test_a_terminal_mission_run_requires_an_end_time() -> None:
    with pytest.raises(DomainValidationError):
        MissionRun(
            engagement_id=ENGAGEMENT,
            mission_id=MISSION,
            state=MissionRunState.COMPLETED,
            started_at=NOW,
            heartbeat_at=NOW,
        )


def test_a_run_is_stale_only_after_the_watchdog_timeout() -> None:
    run = MissionRun(
        engagement_id=ENGAGEMENT,
        mission_id=MISSION,
        started_at=NOW,
        heartbeat_at=NOW,
    )

    assert not run.is_stale(at=NOW + timedelta(seconds=30), timeout_seconds=60)
    assert run.is_stale(at=NOW + timedelta(seconds=120), timeout_seconds=60)


def test_a_finished_run_is_never_considered_stale() -> None:
    run = MissionRun(
        engagement_id=ENGAGEMENT,
        mission_id=MISSION,
        state=MissionRunState.COMPLETED,
        started_at=NOW,
        heartbeat_at=NOW,
        ended_at=NOW,
    )

    assert not run.is_stale(at=NOW + timedelta(days=1), timeout_seconds=60)


def test_a_cycle_cannot_execute_more_actions_than_it_proposed() -> None:
    with pytest.raises(DomainValidationError):
        AgentCycle(
            engagement_id=ENGAGEMENT,
            mission_run_id=new_mission_run_id(),
            index=0,
            state=CycleState.COMPLETED,
            actions_proposed=1,
            actions_executed=2,
            started_at=NOW,
            ended_at=NOW,
        )


def test_asset_and_endpoint_normalization_rules() -> None:
    asset = Asset(
        engagement_id=ENGAGEMENT,
        kind=AssetKind.HOSTNAME,
        identifier="api.example.com",
        first_seen_at=NOW,
        last_seen_at=NOW,
    )

    assert asset.identifier == "api.example.com"
    with pytest.raises(DomainValidationError):
        Endpoint(
            engagement_id=ENGAGEMENT,
            asset_id=new_asset_id(),
            method="get",
            path="/orders",
            first_seen_at=NOW,
            last_seen_at=NOW,
        )
    with pytest.raises(DomainValidationError):
        Endpoint(
            engagement_id=ENGAGEMENT,
            asset_id=new_asset_id(),
            method="GET",
            path="orders",
            first_seen_at=NOW,
            last_seen_at=NOW,
        )


def test_observation_and_candidate_require_content_digests() -> None:
    with pytest.raises(DomainValidationError):
        Observation(
            engagement_id=ENGAGEMENT,
            kind=ObservationKind.HTTP_RESPONSE,
            subject="api.example.com",
            digest="not-a-digest",
            summary="status 200",
            observed_at=NOW,
        )
    with pytest.raises(DomainValidationError):
        Candidate(
            engagement_id=ENGAGEMENT,
            source=CandidateSource.SCANNER,
            tool_name="nuclei",
            title="exposed panel",
            category="exposure",
            target="https://api.example.com/",
            raw_digest="short",
            created_at=NOW,
        )


def test_a_change_event_requires_at_least_one_digest() -> None:
    with pytest.raises(DomainValidationError):
        ChangeEvent(
            engagement_id=ENGAGEMENT,
            kind=ChangeKind.ENDPOINT_ADDED,
            subject="endpoint:GET:/orders",
            snapshot_id=new_surface_snapshot_id(),
            detected_at=NOW,
        )


def test_surface_snapshot_counts_must_not_be_negative() -> None:
    with pytest.raises(DomainValidationError):
        SurfaceSnapshot(
            engagement_id=ENGAGEMENT,
            digest=DIGEST,
            asset_count=-1,
            endpoint_count=0,
            captured_at=NOW,
        )
