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
from typing import Final

from vuln_proof_claw.agent.authsession import IdentitySessions, ProbeError
from vuln_proof_claw.agent.differential import (
    ANONYMOUS,
    OracleVerdict,
    ProbeResult,
    evaluate_all,
)
from vuln_proof_claw.agent.endpoints import (
    EndpointClassification,
    EndpointRisk,
    ProbeStrategy,
)
from vuln_proof_claw.domain.errors import DomainValidationError

_LOGGER = logging.getLogger(__name__)

_SECONDS_PER_MINUTE = 60.0


@dataclass(frozen=True, slots=True)
class EndpointSpec:
    """One endpoint to compare across identities.

    The strategy and the method are validated together. A sweep that could send any
    method under any strategy would carry no constraint, so the two legal pairings are
    fixed here: a direct read, or a POST carrying nothing.
    """

    method: str
    path: str
    strategy: ProbeStrategy = ProbeStrategy.DIRECT

    def __post_init__(self) -> None:
        normalized = self.method.upper()
        if self.strategy is ProbeStrategy.REFUSE:
            raise DomainValidationError("a refused endpoint is never swept")
        if self.strategy is ProbeStrategy.DIRECT and normalized not in {"GET", "HEAD"}:
            raise DomainValidationError("sweeps only read; method must be GET or HEAD")
        if self.strategy is ProbeStrategy.EMPTY_BODY and normalized != "POST":
            raise DomainValidationError("an empty-body probe is sent as POST only")
        if not self.path.startswith("/"):
            raise DomainValidationError("path must be absolute")
        object.__setattr__(self, "method", normalized)


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
    sent_at: tuple[datetime, ...] = ()
    stopped_early: str | None = None

    @property
    def requests_sent(self) -> int:
        return len(self.sent_at)

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
    on_request: Callable[[datetime], None] | None = None
    """Called with the moment of each request, as it is sent.

    The caller charges its budget here rather than from the batch this returns. A
    paced sweep of two hundred endpoints runs for an hour and a half, and for all of
    it the ledger said nothing had been spent -- so the budget could not see work in
    flight, and neither could anyone trying to tell a long sweep from a stuck one.

    I could not tell them apart either, and said the agent had hung when it was
    working.
    """

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
        sent: list[datetime] = []
        consecutive_errors = 0
        stopped: str | None = None

        for endpoint in endpoints:
            target = self._absolute(endpoint.path)
            probes: list[ProbeResult] = []
            error: str | None = None

            for identity in identities:
                if sent:
                    self._pace()
                moment = self.clock()
                try:
                    probes.append(
                        self.sessions.probe(
                            identity,
                            endpoint.method,
                            target,
                            strategy=endpoint.strategy,
                            at=moment,
                        )
                    )
                    consecutive_errors = 0
                except ProbeError as failure:
                    error = str(failure)
                    consecutive_errors += 1
                    _LOGGER.warning("probe failed for %s as %s: %s", target, identity, failure)
                finally:
                    sent.append(moment)
                    if self.on_request is not None:
                        self.on_request(moment)

                if consecutive_errors >= self.policy.maximum_consecutive_errors:
                    stopped = "consecutive_probe_errors"
                    break

            # One probe is enough to run the oracles. The comparison rules each refuse
            # on their own when an identity they need is missing, while
            # check_missing_authentication is not a comparison at all: the signal is the
            # kind of answer an anonymous caller gets, which one observation carries.
            # Requiring two here silenced exactly that rule whenever no credentials were
            # configured, which is the most common way this runs.
            verdicts = (
                evaluate_all(probes, owner=owner, other=other, privileged=privileged)
                if probes
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

        return SweepReport(tuple(outcomes), sent_at=tuple(sent), stopped_early=stopped)

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


@dataclass(frozen=True, slots=True)
class ProbeOutcome:
    """What one sweep observed, reduced to what a scheduler needs.

    ``sent_at`` carries the moment each request actually left, not how many there were.
    A sweep paces itself across minutes, so charging the whole batch to the instant the
    cycle began would record a burst that never happened — and a rate limit is answered
    by when requests were sent, not by how many a cycle produced in total.
    """

    verdicts: tuple[OracleVerdict, ...] = ()
    sent_at: tuple[datetime, ...] = ()
    stopped_early: str | None = None

    @property
    def requests_sent(self) -> int:
        return len(self.sent_at)


@dataclass
class SweepProber:
    """Adapt a differential sweep to the controller's probing contract.

    The identities are authenticated once and reused across cycles. An identity whose
    session has expired fails its probes, which the sweep contains and reports; the next
    cycle re-authenticates rather than retrying inside one.
    """

    sweep: DifferentialSweep
    owner: str
    other: str | None = None
    privileged: str | None = None
    include_anonymous: bool = True
    on_request: Callable[[datetime], None] | None = None
    _ready: bool = field(default=False, init=False, repr=False)

    def probe(
        self,
        endpoints: Sequence[EndpointSpec],
        *,
        at: datetime,
        on_request: Callable[[datetime], None] | None = None,
    ) -> ProbeOutcome:
        """Authenticate if needed, sweep the planned endpoints, and judge the results."""
        self._ensure_sessions(at=at)
        reporter = on_request or self.on_request
        if reporter is not None:
            self.sweep.on_request = reporter
        report = self.sweep.run(
            endpoints,
            owner=self.owner,
            other=self.other,
            privileged=self.privileged,
            include_anonymous=self.include_anonymous,
        )
        verdicts = tuple(
            verdict for outcome in report.outcomes for verdict in outcome.verdicts
        )
        return ProbeOutcome(
            verdicts=verdicts,
            sent_at=report.sent_at,
            stopped_early=report.stopped_early,
        )

    def _ensure_sessions(self, *, at: datetime) -> None:
        if self._ready:
            return
        seen: set[str] = set()
        for identity in (self.owner, self.other, self.privileged, ANONYMOUS):
            if identity is None or identity in seen:
                continue
            seen.add(identity)
            self.sweep.sessions.authenticate(identity, at=at)
        self._ready = True


@dataclass(frozen=True, slots=True)
class SweepPlan:
    """What an unattended sweep will probe, and what it will not."""

    endpoints: tuple[EndpointSpec, ...] = ()
    withheld: tuple[tuple[str, str], ...] = ()
    """Each withheld endpoint's path and the reason it was left out."""

    def __len__(self) -> int:
        return len(self.endpoints)


#: Endpoints that are not destructive and change nothing, but make the target spend
#: a fixed stretch of time on the request. Go's `/debug/pprof/profile` runs a CPU
#: profile for thirty seconds by default, and `trace` the same; calling either on a
#: schedule is a load test of somebody else's system under another name, which the
#: activity rules forbid outright.
#:
#: Deliberately specific. "Expensive" in general is a judgement about a system we
#: cannot see; these are endpoints whose published contract is "block and measure".
_TIMED_WORK: Final = (
    "/debug/pprof/profile",
    "/debug/pprof/trace",
    "/debug/pprof/block",
    "/debug/pprof/mutex",
)


def _runs_for_a_while(path: str) -> bool:
    """Return whether calling this path makes the target work for a set duration."""
    return any(path.endswith(suffix) for suffix in _TIMED_WORK)


def plan_sweep(
    classifications: Sequence[EndpointClassification],
    *,
    limit: int,
    include_mutating: bool = False,
) -> SweepPlan:
    """Choose which recovered endpoints an unattended agent may probe.

    Three things are withheld, and the reason travels with each so an operator can see
    what the agent declined rather than having to infer it:

    * **Destructive endpoints.** Never called, under any setting.
    * **Mutating endpoints.** Withheld by default. An empty-body POST to ``setX`` is
      still a write attempt, and autonomous execution is capped at L1; a human decides
      whether to make it. ``include_mutating`` is for an operator who has.
    * **Placeholders in a path segment.** ``/api/companies/{param}/members`` has no
      meaning until something supplies an identifier. Probing the literal placeholder
      would produce a 404 and a confident-looking verdict about nothing.

    A placeholder in the *query* is different, and the distinction matters. Dropping
    ``?adminUuid={param}`` leaves ``/api/getCompanyDisplay``, a request the server will
    route and answer. Omitting a required parameter is how you learn whether the
    rejection comes from the authentication layer or the validation layer behind it —
    which is the whole question. A path segment cannot be dropped the same way,
    because what is left is a different endpoint.

    ``limit`` bounds the plan to what the mission's remaining request budget allows.
    """
    if limit < 0:
        raise DomainValidationError("limit must not be negative")

    chosen: list[EndpointSpec] = []
    withheld: list[tuple[str, str]] = []
    for item in classifications:
        if item.risk is EndpointRisk.DESTRUCTIVE:
            withheld.append((item.path, "destructive"))
            continue
        if item.risk is EndpointRisk.MUTATING and not include_mutating:
            withheld.append((item.path, "mutating_requires_approval"))
            continue
        probeable_path = item.path.split("?", 1)[0]
        if _runs_for_a_while(probeable_path):
            withheld.append((item.path, "asks the target to work for a fixed duration"))
            continue
        if "{" in probeable_path:
            withheld.append((item.path, "parameterised_path_needs_an_identifier"))
            continue
        if len(chosen) >= limit:
            withheld.append((item.path, "request_budget"))
            continue
        try:
            chosen.append(
                EndpointSpec(
                    method=item.method, path=probeable_path, strategy=item.strategy
                )
            )
        except DomainValidationError as refusal:
            # A classification the spec will not accept is a disagreement between two
            # of our own rules, not a reason to abandon the other two hundred
            # endpoints. It is withheld with the refusal attached so the disagreement
            # is visible instead of arriving as a cycle that fails nine times running.
            withheld.append((item.path, f"not probeable: {refusal}"))
    return SweepPlan(endpoints=tuple(chosen), withheld=tuple(withheld))


__all__ = [
    "DifferentialSweep",
    "EndpointOutcome",
    "EndpointSpec",
    "ProbeOutcome",
    "SweepPlan",
    "SweepPolicy",
    "SweepProber",
    "SweepReport",
    "plan_sweep",
    "probe_plan_size",
    "summarise",
]
