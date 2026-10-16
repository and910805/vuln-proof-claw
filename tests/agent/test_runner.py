"""Tests for the unattended mission supervisor.

The supervisor exists to survive things, so the tests are mostly about what must not
kill a multi-day run: a failing cycle, a dropped connection, a paused mission.
"""

from __future__ import annotations

from collections.abc import Iterator
from contextlib import contextmanager
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from threading import Event

import pytest

from vuln_proof_claw.agent.controller import CycleReport, MissionControllerError
from vuln_proof_claw.agent.runner import (
    MissionRunner,
    RunnerConfig,
    RunnerReport,
)
from vuln_proof_claw.domain.autonomous import AgentCycle, MissionRun
from vuln_proof_claw.domain.enums import CycleState
from vuln_proof_claw.domain.errors import DomainValidationError
from vuln_proof_claw.domain.identifiers import new_engagement_id, new_mission_id
from vuln_proof_claw.persistence.repositories import Stored

NOW = datetime(2026, 10, 4, 12, 0, tzinfo=UTC)
ENGAGEMENT = new_engagement_id()
MISSION = new_mission_id()


def make_report(index: int = 0) -> CycleReport:
    run = MissionRun(
        engagement_id=ENGAGEMENT, mission_id=MISSION, started_at=NOW, heartbeat_at=NOW
    )
    cycle = AgentCycle(
        engagement_id=ENGAGEMENT,
        mission_run_id=run.id,
        index=index,
        state=CycleState.COMPLETED,
        started_at=NOW,
        ended_at=NOW,
    )
    return CycleReport(
        cycle=cycle,
        run=Stored(run, 1),
        outcomes=(),
        changes_detected=0,
        next_cycle_at=NOW + timedelta(seconds=300),
    )


@dataclass
class FakeController:
    """A controller whose behaviour each cycle is scripted by the test."""

    script: list[object] = field(default_factory=list)
    calls: int = 0
    recovered: int = 0
    finished: int = 0

    def recover(self, *, watchdog_seconds: int = 900) -> tuple[str, ...]:
        self.recovered += 1
        return ()

    def start_run(self) -> Stored[MissionRun]:
        return make_report().run

    def run_cycle(self, stored_run: Stored[MissionRun]) -> CycleReport:
        step = self.script[min(self.calls, len(self.script) - 1)]
        self.calls += 1
        if isinstance(step, Exception):
            raise step
        return make_report(self.calls)

    def finish_run(self, stored_run: Stored[MissionRun], **_: object) -> Stored[MissionRun]:
        self.finished += 1
        return stored_run


def factory_for(controller: FakeController) -> object:
    @contextmanager
    def factory() -> Iterator[FakeController]:
        yield controller

    return factory


@dataclass
class Clock:
    """A sleeper that counts naps and stops the loop after a budget."""

    stop: Event
    budget: int
    naps: list[float] = field(default_factory=list)

    def __call__(self, seconds: float) -> bool:
        self.naps.append(seconds)
        if len(self.naps) >= self.budget:
            self.stop.set()
        return self.stop.is_set()


def run(
    controller: FakeController,
    *,
    budget: int = 3,
    config: RunnerConfig | None = None,
) -> tuple[RunnerReport, Clock]:
    stop = Event()
    sleeper = Clock(stop, budget)
    runner = MissionRunner(
        controller_factory=factory_for(controller),  # type: ignore[arg-type]
        config=config or RunnerConfig(),
        clock=lambda: NOW,
        sleeper=sleeper,
    )
    return (runner.run_forever(stop), sleeper)


def test_backoff_doubles_and_is_capped() -> None:
    config = RunnerConfig(initial_backoff_seconds=5, maximum_backoff_seconds=100)

    assert config.backoff_for(0) == 0
    assert config.backoff_for(1) == 5
    assert config.backoff_for(2) == 10
    assert config.backoff_for(3) == 20
    assert config.backoff_for(99) == 100


@pytest.mark.parametrize(
    "overrides",
    [
        {"maximum_consecutive_failures": 0},
        {"initial_backoff_seconds": 0},
        {"initial_backoff_seconds": 100, "maximum_backoff_seconds": 10},
        {"paused_poll_seconds": 0},
    ],
)
def test_an_incoherent_policy_is_refused(overrides: dict[str, int]) -> None:
    with pytest.raises(DomainValidationError):
        RunnerConfig(**overrides)


def test_it_recovers_once_before_the_first_cycle() -> None:
    controller = FakeController(script=[None])

    report, _ = run(controller, budget=1)

    assert controller.recovered == 1
    assert report.cycles_completed >= 1


def test_it_keeps_cycling_until_asked_to_stop() -> None:
    controller = FakeController(script=[None])

    report, sleeper = run(controller, budget=3)

    assert report.stopped_because == "stopped"
    assert report.cycles_completed == 3
    assert report.cycles_failed == 0
    assert sleeper.naps == [300.0, 300.0, 300.0]


def test_a_failing_cycle_does_not_kill_the_run() -> None:
    """This is the property the whole module exists for."""
    controller = FakeController(script=[RuntimeError("database went away"), None])

    report, sleeper = run(controller, budget=3)

    assert report.cycles_failed == 1
    assert report.cycles_completed >= 1
    assert report.stopped_because == "stopped"
    assert sleeper.naps[0] == 5  # backed off before retrying


def test_consecutive_failures_eventually_stop_the_run() -> None:
    controller = FakeController(script=[RuntimeError("boom")])
    config = RunnerConfig(maximum_consecutive_failures=3, initial_backoff_seconds=1)

    report, _ = run(controller, budget=99, config=config)

    assert report.stopped_because == "failure_limit"
    assert report.cycles_failed == 3
    assert report.last_error is not None
    assert "boom" in report.last_error


def test_a_success_resets_the_failure_streak() -> None:
    controller = FakeController(script=[RuntimeError("blip"), None, RuntimeError("blip"), None])
    config = RunnerConfig(maximum_consecutive_failures=2, initial_backoff_seconds=1)

    report, _ = run(controller, budget=6, config=config)

    assert report.stopped_because == "stopped"
    assert report.cycles_failed == 2


def test_a_paused_mission_waits_instead_of_burning_the_failure_budget() -> None:
    controller = FakeController(script=[MissionControllerError("mission_paused")])
    config = RunnerConfig(maximum_consecutive_failures=2, paused_poll_seconds=30)

    report, sleeper = run(controller, budget=4, config=config)

    assert report.stopped_because == "stopped"
    assert report.cycles_failed == 0
    assert sleeper.naps == [30, 30, 30, 30]


def test_the_kill_switch_is_treated_as_waiting_not_failure() -> None:
    controller = FakeController(script=[MissionControllerError("kill_switch_engaged")])

    report, _ = run(controller, budget=2)

    assert report.cycles_failed == 0
    assert report.last_error == "kill_switch_engaged"


@pytest.mark.parametrize("reason", ["mission_not_found", "mission_expired"])
def test_an_unrecoverable_condition_stops_immediately(reason: str) -> None:
    controller = FakeController(script=[MissionControllerError(reason)])

    report, sleeper = run(controller, budget=99)

    assert report.stopped_because == "fatal"
    assert report.last_error == reason
    assert sleeper.naps == []


def test_an_unknown_controller_error_is_treated_as_transient() -> None:
    """An unrecognised failure should back off and retry, not stop a multi-day run."""
    controller = FakeController(script=[MissionControllerError("something_new")])
    config = RunnerConfig(maximum_consecutive_failures=2, initial_backoff_seconds=1)

    report, _ = run(controller, budget=99, config=config)

    assert report.stopped_because == "failure_limit"
    assert report.cycles_failed == 2


def test_a_failure_during_recovery_does_not_prevent_starting() -> None:
    @dataclass
    class Breaking(FakeController):
        def recover(self, *, watchdog_seconds: int = 900) -> tuple[str, ...]:
            raise RuntimeError("recovery exploded")

    controller = Breaking(script=[None])

    report, _ = run(controller, budget=1)

    assert report.cycles_completed == 1


def test_each_cycle_closes_its_run() -> None:
    """A finished run must not be left RUNNING for the watchdog to reap."""
    controller = FakeController(script=[None])

    run(controller, budget=2)

    assert controller.finished == 2


def test_a_bounded_run_stops_after_the_cycles_it_was_given() -> None:
    """An engagement with several targets and one concurrency budget works them in
    turn, and a loop that never ends cannot be taken in turns."""
    controller = FakeController(script=[None] * 5)
    runner = MissionRunner(
        controller_factory=factory_for(controller),  # type: ignore[arg-type]
        config=RunnerConfig(maximum_cycles=2, initial_backoff_seconds=1),
    )

    report = runner.run_forever(Event())

    assert report.cycles_completed == 2
    assert report.stopped_because == "cycle_limit"


def test_zero_means_run_until_asked_to_stop() -> None:
    """The default stays what it was: an unattended agent is not a batch job."""
    assert RunnerConfig().maximum_cycles == 0


def test_a_negative_cycle_limit_is_refused() -> None:
    with pytest.raises(DomainValidationError, match="maximum_cycles"):
        RunnerConfig(maximum_cycles=-1)
