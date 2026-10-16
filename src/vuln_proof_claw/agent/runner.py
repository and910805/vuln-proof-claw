"""Long-running supervisor for an autonomous mission.

The controller knows how to perform one cycle. This module keeps performing them for
days without supervision, which requires answering three questions the controller does
not:

* **What survives a failure?** A cycle that raises must not take the process with it.
  Transient faults back off and retry; a paused mission waits rather than spinning; only
  a genuinely unrecoverable condition stops the loop.
* **What holds the database connection?** Nothing, for long. Each cycle borrows a fresh
  session from a factory and returns it, so a connection dropped overnight costs one
  cycle rather than the run.
* **How does it stop?** Through a cooperative event, so a signal handler can ask for a
  clean shutdown and the current cycle finishes instead of being torn open.

Nothing here decides what to test. It only decides whether to keep going.
"""

from __future__ import annotations

import logging
from collections.abc import Callable
from contextlib import AbstractContextManager
from dataclasses import dataclass, field
from datetime import UTC, datetime
from threading import Event

from vuln_proof_claw.agent.controller import (
    DEFAULT_WATCHDOG_SECONDS,
    CycleReport,
    MissionController,
    MissionControllerError,
)
from vuln_proof_claw.domain.enums import MissionRunState
from vuln_proof_claw.domain.errors import DomainValidationError


def _utc_now() -> datetime:
    return datetime.now(UTC)


_LOGGER = logging.getLogger(__name__)

ControllerFactory = Callable[[], AbstractContextManager[MissionController]]

#: Conditions where the mission is deliberately not running. The supervisor waits and
#: re-checks instead of treating these as failures, so pausing a mission overnight does
#: not exhaust the failure budget.
WAITING_REASONS: frozenset[str] = frozenset(
    {
        "mission_paused",
        "kill_switch_engaged",
        "mission_not_schedulable_pending",
        "mission_not_schedulable_completed",
        "mission_not_schedulable_stopped",
    }
)

#: Conditions that will never resolve on their own.
FATAL_REASONS: frozenset[str] = frozenset(
    {
        "mission_not_found",
        "mission_expired",
        "engagement_scope_unavailable",
    }
)


@dataclass(frozen=True, slots=True)
class RunnerConfig:
    """Supervision policy for an unattended run."""

    watchdog_seconds: int = DEFAULT_WATCHDOG_SECONDS
    maximum_consecutive_failures: int = 10
    maximum_cycles: int = 0
    """Stop after this many completed cycles. Zero means never.

    An engagement with several targets and one concurrency budget has to work them in
    turn, and a loop that never ends cannot be taken in turns. A bounded run lets a
    scheduler give each target a share and move on, instead of the operator stopping
    one by hand to start the next -- which is how four of them ended up running at
    once.
    """
    initial_backoff_seconds: int = 5
    maximum_backoff_seconds: int = 900
    paused_poll_seconds: int = 60

    def __post_init__(self) -> None:
        if self.maximum_consecutive_failures < 1:
            raise DomainValidationError("maximum_consecutive_failures must be at least one")
        if self.initial_backoff_seconds < 1:
            raise DomainValidationError("initial_backoff_seconds must be at least one")
        if self.maximum_backoff_seconds < self.initial_backoff_seconds:
            raise DomainValidationError("maximum_backoff_seconds must not be below the initial")
        if self.paused_poll_seconds < 1:
            raise DomainValidationError("paused_poll_seconds must be at least one")
        if self.maximum_cycles < 0:
            raise DomainValidationError("maximum_cycles must not be negative")

    def backoff_for(self, consecutive_failures: int) -> int:
        """Return the capped exponential delay after N consecutive failures."""
        if consecutive_failures < 1:
            return 0
        delay = self.initial_backoff_seconds * (2 ** (consecutive_failures - 1))
        return int(min(delay, self.maximum_backoff_seconds))


@dataclass(frozen=True, slots=True)
class RunnerReport:
    """What the supervisor did before returning."""

    cycles_completed: int
    cycles_failed: int
    stopped_because: str
    last_error: str | None = None


@dataclass
class MissionRunner:
    """Keep a mission cycling until asked to stop or unable to continue."""

    controller_factory: ControllerFactory
    config: RunnerConfig = field(default_factory=RunnerConfig)
    clock: Callable[[], datetime] = field(default=_utc_now)
    sleeper: Callable[[float], bool] | None = None

    def run_forever(self, stop: Event) -> RunnerReport:
        """Cycle until ``stop`` is set or the mission cannot continue.

        Returns rather than raising: an unattended process wants a reason it can log and
        act on, not a traceback that loses the counters.
        """
        completed = 0
        failed = 0
        consecutive = 0
        last_error: str | None = None

        self._recover()

        while not stop.is_set():
            try:
                report = self._cycle_once()
            except _WaitingError as waiting:
                _LOGGER.info("mission waiting: %s", waiting.reason)
                last_error = waiting.reason
                if self._wait(stop, self.config.paused_poll_seconds):
                    break
                continue
            except _FatalError as fatal:
                _LOGGER.error("mission cannot continue: %s", fatal.reason)
                return RunnerReport(completed, failed, "fatal", fatal.reason)
            except Exception as error:  # noqa: BLE001 - a cycle must never kill the run
                failed += 1
                consecutive += 1
                last_error = f"{type(error).__name__}: {error}"
                _LOGGER.warning(
                    "cycle failed (%d consecutive): %s", consecutive, last_error
                )
                if consecutive >= self.config.maximum_consecutive_failures:
                    return RunnerReport(completed, failed, "failure_limit", last_error)
                if self._wait(stop, self.config.backoff_for(consecutive)):
                    break
                continue

            completed += 1
            consecutive = 0
            if self.config.maximum_cycles and completed >= self.config.maximum_cycles:
                return RunnerReport(completed, failed, "cycle_limit", last_error)
            if self._wait(stop, self._seconds_until(report.next_cycle_at)):
                break

        return RunnerReport(completed, failed, "stopped", last_error)

    def _recover(self) -> None:
        """Reconcile anything a previous process left behind."""
        try:
            with self.controller_factory() as controller:
                recovered = controller.recover(watchdog_seconds=self.config.watchdog_seconds)
            if recovered:
                _LOGGER.info("recovered %d interrupted run(s)", len(recovered))
        except Exception as error:  # noqa: BLE001 - recovery is best effort at startup
            _LOGGER.warning("recovery failed, continuing: %s", error)

    def _cycle_once(self) -> CycleReport:
        with self.controller_factory() as controller:
            try:
                stored_run = controller.start_run()
                report = controller.run_cycle(stored_run)
            except MissionControllerError as error:
                reason = str(error)
                if reason in FATAL_REASONS:
                    raise _FatalError(reason) from error
                if reason in WAITING_REASONS:
                    raise _WaitingError(reason) from error
                raise
            controller.finish_run(report.run, state=MissionRunState.COMPLETED)
            return report

    def _wait(self, stop: Event, seconds: float) -> bool:
        """Sleep interruptibly. Return True when asked to stop."""
        if seconds <= 0:
            return stop.is_set()
        if self.sleeper is not None:
            return self.sleeper(seconds)
        return stop.wait(timeout=seconds)

    def _seconds_until(self, moment: datetime) -> float:
        delta = (moment - self.clock()).total_seconds()
        return max(0.0, delta)


class _WaitingError(Exception):
    """The mission is deliberately not running right now."""

    def __init__(self, reason: str) -> None:
        super().__init__(reason)
        self.reason = reason


class _FatalError(Exception):
    """The mission cannot continue without operator action."""

    def __init__(self, reason: str) -> None:
        super().__init__(reason)
        self.reason = reason


__all__ = [
    "FATAL_REASONS",
    "WAITING_REASONS",
    "ControllerFactory",
    "MissionRunner",
    "RunnerConfig",
    "RunnerReport",
]
