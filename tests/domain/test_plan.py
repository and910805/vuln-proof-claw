"""Tests for resumable plan progression."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest

from vuln_proof_claw.domain.enums import TaskState
from vuln_proof_claw.domain.errors import DomainValidationError
from vuln_proof_claw.domain.identifiers import new_flow_id
from vuln_proof_claw.domain.models import Task
from vuln_proof_claw.domain.plan import (
    claim,
    is_complete,
    ordered,
    progress,
    resume_point,
    transition,
)

NOW = datetime(2026, 8, 26, 12, 0, tzinfo=UTC)
FLOW = new_flow_id()


def step(sequence: int, state: TaskState = TaskState.PLANNED, attempts: int = 0) -> Task:
    return Task(
        flow_id=FLOW,
        title=f"step {sequence}",
        sequence=sequence,
        state=state,
        attempts=attempts,
        created_at=NOW + timedelta(seconds=sequence),
    )


def test_negative_sequence_or_attempts_is_rejected() -> None:
    with pytest.raises(DomainValidationError):
        step(-1)
    with pytest.raises(DomainValidationError):
        Task(flow_id=FLOW, title="x", attempts=-1, created_at=NOW)


def test_plan_is_ordered_by_sequence_then_creation() -> None:
    plan = (step(2), step(0), step(1))
    assert [task.sequence for task in ordered(plan)] == [0, 1, 2]


def test_resume_point_is_the_first_unfinished_step() -> None:
    plan = (
        step(0, TaskState.COMPLETED),
        step(1, TaskState.ABANDONED),
        step(2, TaskState.FAILED),
        step(3),
    )
    resumed = resume_point(plan)
    assert resumed is not None
    assert resumed.sequence == 2


def test_a_killed_step_left_running_is_resumable() -> None:
    plan = (step(0, TaskState.COMPLETED), step(1, TaskState.RUNNING))
    resumed = resume_point(plan)
    assert resumed is not None
    assert resumed.sequence == 1


def test_finished_plan_has_no_resume_point() -> None:
    plan = (step(0, TaskState.COMPLETED), step(1, TaskState.ABANDONED))
    assert resume_point(plan) is None
    assert is_complete(plan)


def test_progress_counts_only_completed_steps() -> None:
    plan = (
        step(0, TaskState.COMPLETED),
        step(1, TaskState.ABANDONED),
        step(2, TaskState.RUNNING),
    )
    assert progress(plan) == (1, 3)


def test_claiming_a_step_counts_the_attempt() -> None:
    claimed = claim(step(0))
    assert claimed.state is TaskState.RUNNING
    assert claimed.attempts == 1


def test_reclaiming_a_step_whose_worker_died_counts_another_attempt() -> None:
    reclaimed = claim(step(0, TaskState.RUNNING, attempts=1))
    assert reclaimed.state is TaskState.RUNNING
    assert reclaimed.attempts == 2


def test_a_step_that_used_up_its_attempts_is_abandoned_not_retried() -> None:
    abandoned = claim(step(0, TaskState.FAILED, attempts=3), max_attempts=3)
    assert abandoned.state is TaskState.ABANDONED


def test_terminal_steps_cannot_be_claimed_or_moved() -> None:
    with pytest.raises(DomainValidationError):
        claim(step(0, TaskState.COMPLETED))
    with pytest.raises(DomainValidationError):
        transition(step(0, TaskState.COMPLETED), TaskState.RUNNING)


def test_max_attempts_must_allow_at_least_one_try() -> None:
    with pytest.raises(DomainValidationError):
        claim(step(0), max_attempts=0)


@pytest.mark.parametrize(
    ("start", "target"),
    [
        (TaskState.PLANNED, TaskState.COMPLETED),
        (TaskState.PLANNED, TaskState.FAILED),
        (TaskState.FAILED, TaskState.COMPLETED),
        (TaskState.ABANDONED, TaskState.RUNNING),
    ],
)
def test_illegal_transitions_are_refused(start: TaskState, target: TaskState) -> None:
    with pytest.raises(DomainValidationError):
        transition(step(0, start), target)


def test_a_failed_step_can_be_retried() -> None:
    retried = transition(step(0, TaskState.FAILED, attempts=1), TaskState.RUNNING)
    assert retried.state is TaskState.RUNNING
    assert retried.attempts == 2
