"""Tests for cadence-driven scheduling and lead cooldowns."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest

from vuln_proof_claw.agent.scheduler import (
    RecurringTask,
    evaluate_task,
    is_stale,
    next_cycle_at,
    retry_backoff,
    task_interval,
)
from vuln_proof_claw.domain.autonomous import Lead, MissionCadence
from vuln_proof_claw.domain.enums import LeadStatus
from vuln_proof_claw.domain.errors import DomainValidationError
from vuln_proof_claw.domain.identifiers import new_engagement_id, new_mission_id

NOW = datetime(2026, 10, 4, 12, 0, tzinfo=UTC)
CADENCE = MissionCadence()
NAIVE = datetime(2026, 10, 4, 12, 0)


def make_lead(**overrides: object) -> Lead:
    defaults: dict[str, object] = {
        "engagement_id": new_engagement_id(),
        "mission_id": new_mission_id(),
        "title": "Endpoint returns unexpected object",
        "hypothesis": "Ownership may not be enforced",
        "category": "authorization",
        "created_at": NOW,
        "updated_at": NOW,
    }
    defaults.update(overrides)
    return Lead(**defaults)  # type: ignore[arg-type]


def test_intervals_come_from_configuration_not_constants() -> None:
    fast = MissionCadence(http_inventory_seconds=60)
    slow = MissionCadence(http_inventory_seconds=7_200)

    assert task_interval(RecurringTask.HTTP_INVENTORY, fast) == timedelta(seconds=60)
    assert task_interval(RecurringTask.HTTP_INVENTORY, slow) == timedelta(seconds=7_200)


def test_a_task_that_never_ran_is_immediately_due() -> None:
    decision = evaluate_task(
        RecurringTask.DEEP_RECON, CADENCE, last_run_at=None, now=NOW
    )

    assert decision.due
    assert decision.reason == "never_run"


def test_a_task_becomes_due_only_after_its_interval_elapses() -> None:
    interval = task_interval(RecurringTask.HTTP_INVENTORY, CADENCE)

    pending = evaluate_task(
        RecurringTask.HTTP_INVENTORY, CADENCE, last_run_at=NOW, now=NOW + interval / 2
    )
    due = evaluate_task(
        RecurringTask.HTTP_INVENTORY, CADENCE, last_run_at=NOW, now=NOW + interval
    )

    assert not pending.due
    assert pending.reason == "interval_pending"
    assert due.due


def test_next_cycle_uses_the_configured_cycle_interval() -> None:
    cadence = MissionCadence(cycle_interval_seconds=120)

    assert next_cycle_at(cadence, now=NOW) == NOW + timedelta(seconds=120)


def test_retry_backoff_doubles_and_is_capped() -> None:
    cadence = MissionCadence(lead_retry_cooldown_seconds=60)

    first = retry_backoff(1, cadence)
    second = retry_backoff(2, cadence)
    extreme = retry_backoff(1_000, cadence)

    assert first == timedelta(seconds=60)
    assert second == timedelta(seconds=120)
    assert extreme == retry_backoff(7, cadence)


def test_retry_backoff_rejects_negative_failure_counts() -> None:
    with pytest.raises(DomainValidationError):
        retry_backoff(-1, CADENCE)


def test_staleness_is_measured_from_the_last_attempt() -> None:
    cadence = MissionCadence(stale_lead_after_seconds=3_600)
    untouched = make_lead()
    recent = make_lead(attempt_count=1, last_attempt_at=NOW)

    assert is_stale(untouched, cadence, now=NOW + timedelta(hours=2))
    assert not is_stale(recent, cadence, now=NOW + timedelta(minutes=30))


def test_terminal_leads_are_never_marked_stale() -> None:
    closed = make_lead(status=LeadStatus.REJECTED)

    assert not is_stale(closed, CADENCE, now=NOW + timedelta(days=365))


def test_scheduler_rejects_naive_timestamps() -> None:
    with pytest.raises(DomainValidationError):
        next_cycle_at(CADENCE, now=NAIVE)
