"""Plan progression rules that let an interrupted run continue where it stopped.

A run that is killed part-way through - by a budget ceiling, a watchdog, or an
inference engine that aborts every hour or so - loses everything it had done if
only the actions were recorded and not the plan's progress. These rules keep the
plan resumable: the first step that is not finished is where a fresh worker
picks up, and each retry is counted so a step that keeps failing is abandoned
rather than retried forever.
"""

from __future__ import annotations

from collections.abc import Iterable, Sequence
from dataclasses import replace

from vuln_proof_claw.domain.enums import TaskState
from vuln_proof_claw.domain.errors import DomainValidationError
from vuln_proof_claw.domain.models import Task

DEFAULT_MAX_ATTEMPTS = 3

_ALLOWED_TRANSITIONS: dict[TaskState, frozenset[TaskState]] = {
    TaskState.PLANNED: frozenset({TaskState.RUNNING, TaskState.ABANDONED}),
    TaskState.RUNNING: frozenset({TaskState.COMPLETED, TaskState.FAILED, TaskState.ABANDONED}),
    TaskState.FAILED: frozenset({TaskState.RUNNING, TaskState.ABANDONED}),
    TaskState.COMPLETED: frozenset(),
    TaskState.ABANDONED: frozenset(),
}


def ordered(tasks: Iterable[Task]) -> tuple[Task, ...]:
    """Return the plan in execution order, stable for equal sequence numbers."""
    return tuple(sorted(tasks, key=lambda task: (task.sequence, task.created_at, task.id)))


def resume_point(tasks: Iterable[Task]) -> Task | None:
    """Return the first step a fresh worker should take, or None when finished."""
    for task in ordered(tasks):
        if task.state.resumable:
            return task
    return None


def is_complete(tasks: Iterable[Task]) -> bool:
    """Return whether every step has reached a terminal state."""
    return all(task.state.terminal for task in tasks)


def progress(tasks: Sequence[Task]) -> tuple[int, int]:
    """Return completed count over total count, for reporting progress honestly."""
    completed = sum(1 for task in tasks if task.state is TaskState.COMPLETED)
    return completed, len(tasks)


def transition(task: Task, state: TaskState) -> Task:
    """Move one step to a new state, rejecting transitions out of a terminal state."""
    if state not in _ALLOWED_TRANSITIONS[task.state]:
        raise DomainValidationError(f"task cannot move from {task.state.value} to {state.value}")
    if state is TaskState.RUNNING:
        return replace(task, state=state, attempts=task.attempts + 1)
    return replace(task, state=state)


def claim(task: Task, *, max_attempts: int = DEFAULT_MAX_ATTEMPTS) -> Task:
    """Start or retry one step, abandoning it once it has used up its attempts.

    A worker that died leaves its step in ``running``; reclaiming it counts as
    another attempt, so a step that repeatedly kills its worker does not loop.
    """
    if max_attempts < 1:
        raise DomainValidationError("max_attempts must be at least 1")
    if task.state.terminal:
        raise DomainValidationError("a terminal task cannot be claimed")
    if task.attempts >= max_attempts:
        return replace(task, state=TaskState.ABANDONED)
    if task.state is TaskState.RUNNING:
        return replace(task, attempts=task.attempts + 1)
    return transition(task, TaskState.RUNNING)
