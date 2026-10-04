"""Drive differential probes across an endpoint inventory.

This is the piece that turns a list of endpoints into oracle verdicts. It owns three
responsibilities the oracles deliberately do not:

* **Pacing.** Requests are spaced to a configured rate. The activity rules forbid 大量
  掃描, and a sweep that outruns a human operator is exactly that.
* **Ordering.** All identities probe one endpoint before moving to the next, so a
  verdict compares responses taken close together rather than hours apart. A server
  that changes state between probes would otherwise produce a false difference.
* **Containment.** A failure on one endpoint is recorded and the sweep continues; one
  unreachable path must not abandon the remaining inventory.

Verdicts become candidates, never findings. Promotion still requires verification.
"""

from __future__ import annotations

import logging
import time
from collections.abc import Callable, Iterable, Sequence
from dataclasses import dataclass, field
from datetime import UTC, datetime

from vuln_proof_claw.agent.authsession import IdentitySessions, ProbeError
from vuln_proof_claw.agent.differential import (
    ANONYMOUS,
    OracleVerdict,
    ProbeResult,
    evaluate_all,
)
from vuln_proof_claw.domain.errors import DomainValidationError

_LOGGER = logging.getLogger(__name__)

_SECONDS_PER_MINUTE = 60.0


@dataclass(frozen=True, slots=True)
class EndpointSpec:
    """One endpoint to compare across identities."""

    method: str
    path: str

    def __post_init__(self) -> None:
        if self.method.upper() not in {"GET", "HEAD"}:
            raise DomainValidationError("sweeps only read; method must be GET or HEAD")
        if not self.path.startswith("/"):
            raise DomainValidationError("path must be absolute")
        object.__setattr__(self, "method", self.method.upper())


@dataclass(frozen=True, slots=True)
class SweepPolicy:
    """How fast a sweep may run and how much it may tolerate."""

    requests_per_minute: int = 30
    maximum_consecutive_errors: int = 5

    def __post_init__(self) -> None:
        if not 1 <= self.requests_per_minute <= 600:  # noqa: PLR2004 - explicit sane band
            raise DomainValidationError("requests_per_minute must be between 1 and 600")
        if self.maximum_consecutive_errors < 1:
            raise DomainValidationError("maximum_consecutive_errors must be at least one")

    @property
    def interval_seconds(self) -> float:
        return _SECONDS_PER_MINUTE / self.requests_per_minute


@dataclass(frozen=True, slots=True)
class EndpointOutcome:
    """Everything observed and concluded about one endpoint."""

    endpoint: EndpointSpec
    target: str
    probes: tuple[ProbeResult, ...]
    verdicts: tuple[OracleVerdict, ...]
    error: str | None = None

    @property
    def triggered(self) -> tuple[OracleVerdict, ...]:
        return tuple(verdict for verdict in self.verdicts if verdict.triggered)


@dataclass(frozen=True, slots=True)
class SweepReport:
    """What a whole sweep observed."""

    outcomes: tuple[EndpointOutcome, ...]
    requests_sent: int
    stopped_early: str | None = None

    @property
    def triggered(self) -> tuple[EndpointOutcome, ...]:
        return tuple(outcome for outcome in self.outcomes if outcome.triggered)


@dataclass
class DifferentialSweep:
    """Compare a set of endpoints across a set of identities."""

    sessions: IdentitySessions
    base_url: str
    policy: SweepPolicy = field(default_factory=SweepPolicy)
    clock: Callable[[], datetime] = field(default=lambda: datetime.now(UTC))
    pacer: Callable[[float], None] | None = None

    def run(
        self,
        endpoints: Iterable[EndpointSpec],
        *,
        owner: str,
        other: str | None = None,
        privileged: str | None = None,
        include_anonymous: bool = True,
    ) -> SweepReport:
        """Probe every endpoint as every identity and judge the differences."""
        identities = self._identity_order(
            owner=owner, other=other, privileged=privileged, include_anonymous=include_anonymous
        )
        outcomes: list[EndpointOutcome] = []
        sent = 0
        consecutive_errors = 0
        stopped: str | None = None

        for endpoint in endpoints:
            target = self._absolute(endpoint.path)
            probes: list[ProbeResult] = []
            error: str | None = None

            for identity in identities:
                if sent:
                    self._pace()
                try:
                    probes.append(
                        self.sessions.probe(identity, endpoint.method, target, at=self.clock())
                    )
                    consecutive_errors = 0
                except ProbeError as failure:
                    error = str(failure)
                    consecutive_errors += 1
                    _LOGGER.warning("probe failed for %s as %s: %s", target, identity, failure)
                finally:
                    sent += 1

                if consecutive_errors >= self.policy.maximum_consecutive_errors:
                    stopped = "consecutive_probe_errors"
                    break

            verdicts = (
                evaluate_all(probes, owner=owner, other=other, privileged=privileged)
                if len(probes) >= 2  # noqa: PLR2004 - a comparison needs two observations
                else ()
            )
            outcomes.append(
                EndpointOutcome(
                    endpoint=endpoint,
                    target=target,
                    probes=tuple(probes),
                    verdicts=verdicts,
                    error=error,
                )
            )
            if stopped:
                break

        return SweepReport(tuple(outcomes), requests_sent=sent, stopped_early=stopped)

    def _identity_order(
        self,
        *,
        owner: str,
        other: str | None,
        privileged: str | None,
        include_anonymous: bool,
    ) -> tuple[str, ...]:
        """Return the probe order, owner first so a failure there is visible early."""
        order = [owner]
        for candidate in (other, privileged):
            if candidate and candidate not in order:
                order.append(candidate)
        if include_anonymous and ANONYMOUS not in order:
            order.append(ANONYMOUS)
        return tuple(order)

    def _absolute(self, path: str) -> str:
        return f"{self.base_url.rstrip('/')}{path}"

    def _pace(self) -> None:
        if self.pacer is not None:
            self.pacer(self.policy.interval_seconds)
            return
        time.sleep(self.policy.interval_seconds)


def summarise(report: SweepReport) -> tuple[str, ...]:
    """Render one line per triggered verdict, for an operator to read."""
    lines: list[str] = []
    for outcome in report.triggered:
        lines.extend(verdict.as_summary() for verdict in outcome.triggered)
    return tuple(lines)


def probe_plan_size(endpoints: Sequence[EndpointSpec], identities: int) -> int:
    """Return how many requests a sweep will send, for a budget check before starting."""
    return len(endpoints) * max(identities, 0)


__all__ = [
    "DifferentialSweep",
    "EndpointOutcome",
    "EndpointSpec",
    "SweepPolicy",
    "SweepReport",
    "probe_plan_size",
    "summarise",
]
