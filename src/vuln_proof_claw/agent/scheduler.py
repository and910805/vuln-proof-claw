"""Deterministic cadence and cooldown computation.

No interval is hardcoded here. Every duration comes from the engagement's
:class:`~vuln_proof_claw.domain.autonomous.MissionCadence`, so programs with different
rate expectations are served by identical code.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta
from enum import StrEnum

from vuln_proof_claw.domain.autonomous import Lead, MissionCadence
from vuln_proof_claw.domain.enums import LeadStatus
from vuln_proof_claw.domain.errors import DomainValidationError

_MAXIMUM_BACKOFF_EXPONENT = 6


class RecurringTask(StrEnum):
    """Periodic reconnaissance work driven by mission cadence."""

    HTTP_INVENTORY = "http_inventory"
    SUBDOMAIN_REFRESH = "subdomain_refresh"
    DEEP_RECON = "deep_recon"


@dataclass(frozen=True, slots=True)
class ScheduleDecision:
    """Whether a recurring task is due, and when it next becomes due."""

    due: bool
    due_at: datetime
    reason: str


def _require_aware(value: datetime, field_name: str) -> None:
    if value.tzinfo is None or value.utcoffset() is None:
        raise DomainValidationError(f"{field_name} must be timezone-aware")


def task_interval(task: RecurringTask, cadence: MissionCadence) -> timedelta:
    """Return the configured interval for one recurring task."""
    seconds = {
        RecurringTask.HTTP_INVENTORY: cadence.http_inventory_seconds,
        RecurringTask.SUBDOMAIN_REFRESH: cadence.subdomain_refresh_seconds,
        RecurringTask.DEEP_RECON: cadence.deep_recon_seconds,
    }[task]
    return timedelta(seconds=seconds)


def evaluate_task(
    task: RecurringTask,
    cadence: MissionCadence,
    *,
    last_run_at: datetime | None,
    now: datetime,
) -> ScheduleDecision:
    """Return whether a recurring task should run now."""
    _require_aware(now, "now")
    if last_run_at is None:
        return ScheduleDecision(due=True, due_at=now, reason="never_run")
    _require_aware(last_run_at, "last_run_at")
    due_at = last_run_at + task_interval(task, cadence)
    if now >= due_at:
        return ScheduleDecision(due=True, due_at=due_at, reason="interval_elapsed")
    return ScheduleDecision(due=False, due_at=due_at, reason="interval_pending")


def next_cycle_at(cadence: MissionCadence, *, now: datetime) -> datetime:
    """Return when the controller should begin its next cycle."""
    _require_aware(now, "now")
    return now + timedelta(seconds=cadence.cycle_interval_seconds)


def retry_backoff(failure_count: int, cadence: MissionCadence) -> timedelta:
    """Return the capped exponential cooldown for a lead with repeated failures.

    The base cooldown doubles with each consecutive failure up to a fixed ceiling, so a
    persistently failing hypothesis backs off instead of consuming the request budget.
    """
    if failure_count < 0:
        raise DomainValidationError("failure_count must not be negative")
    exponent = min(max(failure_count - 1, 0), _MAXIMUM_BACKOFF_EXPONENT)
    return timedelta(seconds=cadence.lead_retry_cooldown_seconds * (2**exponent))


def next_attempt_at(lead: Lead, cadence: MissionCadence, *, now: datetime) -> datetime:
    """Return when a lead may next be attempted."""
    _require_aware(now, "now")
    return now + retry_backoff(lead.failure_count, cadence)


def is_stale(lead: Lead, cadence: MissionCadence, *, now: datetime) -> bool:
    """Return whether a lead has gone untouched long enough to be marked stale."""
    _require_aware(now, "now")
    if lead.status.terminal or lead.status is LeadStatus.STALE:
        return False
    reference = lead.last_attempt_at or lead.created_at
    return (now - reference) >= timedelta(seconds=cadence.stale_lead_after_seconds)


__all__ = [
    "RecurringTask",
    "ScheduleDecision",
    "evaluate_task",
    "is_stale",
    "next_attempt_at",
    "next_cycle_at",
    "retry_backoff",
    "task_interval",
]
