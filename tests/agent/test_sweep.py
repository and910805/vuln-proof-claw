"""Tests for the differential sweep driver."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import UTC, datetime

import pytest

from tests.agent.support import TARGET_HOST
from vuln_proof_claw.agent.authsession import ProbeError
from vuln_proof_claw.agent.differential import ANONYMOUS, OracleRule, ProbeResult, body_digest
from vuln_proof_claw.agent.sweep import (
    DifferentialSweep,
    EndpointSpec,
    SweepPolicy,
    probe_plan_size,
    summarise,
)
from vuln_proof_claw.domain.errors import DomainValidationError

NOW = datetime(2026, 10, 4, 12, 0, tzinfo=UTC)
BASE = f"https://{TARGET_HOST}"
OWNER_DIGEST = body_digest(b"owner-visible-record" * 20)
DENIED_DIGEST = body_digest(b"forbidden" * 4)


@dataclass
class ScriptedSessions:
    """Returns a scripted response per (identity, path)."""

    responses: dict[tuple[str, str], tuple[int, str, int]] = field(default_factory=dict)
    default: tuple[int, str, int] = (403, DENIED_DIGEST, 40)
    failures: set[tuple[str, str]] = field(default_factory=set)
    calls: list[tuple[str, str]] = field(default_factory=list)

    def probe(
        self, identity: str, method: str, target: str, *, at: datetime | None = None
    ) -> ProbeResult:
        path = target.replace(BASE, "")
        self.calls.append((identity, path))
        if (identity, path) in self.failures:
            raise ProbeError("target unreachable")
        status, digest, size = self.responses.get((identity, path), self.default)
        return ProbeResult(
            identity=identity,
            method=method,
            target=f"{BASE}:443{path}",
            status_code=status,
            body_digest=digest,
            body_size=size,
        )


def build(sessions: ScriptedSessions, *, policy: SweepPolicy | None = None) -> DifferentialSweep:
    naps: list[float] = []
    sweep = DifferentialSweep(
        sessions=sessions,  # type: ignore[arg-type]
        base_url=BASE,
        policy=policy or SweepPolicy(),
        clock=lambda: NOW,
        pacer=naps.append,
    )
    sweep.naps = naps  # type: ignore[attr-defined]
    return sweep


def test_endpoint_spec_only_accepts_reads() -> None:
    with pytest.raises(DomainValidationError, match="only read"):
        EndpointSpec(method="POST", path="/web/x")
    with pytest.raises(DomainValidationError, match="absolute"):
        EndpointSpec(method="GET", path="web/x")
    assert EndpointSpec(method="get", path="/web/x").method == "GET"


def test_an_unreasonable_rate_is_refused() -> None:
    with pytest.raises(DomainValidationError):
        SweepPolicy(requests_per_minute=0)
    with pytest.raises(DomainValidationError):
        SweepPolicy(requests_per_minute=10_000)
    with pytest.raises(DomainValidationError):
        SweepPolicy(maximum_consecutive_errors=0)


def test_the_interval_follows_the_configured_rate() -> None:
    assert SweepPolicy(requests_per_minute=30).interval_seconds == pytest.approx(2.0)
    assert SweepPolicy(requests_per_minute=60).interval_seconds == pytest.approx(1.0)


def test_a_leak_across_two_users_is_reported() -> None:
    sessions = ScriptedSessions(
        responses={
            ("account24", "/web/files/42"): (200, OWNER_DIGEST, 400),
            ("account25", "/web/files/42"): (200, OWNER_DIGEST, 400),
            (ANONYMOUS, "/web/files/42"): (401, DENIED_DIGEST, 40),
        }
    )
    sweep = build(sessions)

    report = sweep.run(
        [EndpointSpec("GET", "/web/files/42")], owner="account24", other="account25"
    )

    assert len(report.triggered) == 1
    rules = {verdict.rule for verdict in report.triggered[0].triggered}
    assert OracleRule.HORIZONTAL_PRIVILEGE in rules
    assert report.requests_sent == 3


def test_a_properly_isolated_endpoint_is_not_reported() -> None:
    sessions = ScriptedSessions(
        responses={
            ("account24", "/web/files/42"): (200, OWNER_DIGEST, 400),
            ("account25", "/web/files/42"): (403, DENIED_DIGEST, 40),
            (ANONYMOUS, "/web/files/42"): (401, DENIED_DIGEST, 40),
        }
    )
    sweep = build(sessions)

    report = sweep.run(
        [EndpointSpec("GET", "/web/files/42")], owner="account24", other="account25"
    )

    assert report.triggered == ()


def test_all_identities_probe_one_endpoint_before_moving_on() -> None:
    """Comparing responses taken far apart would produce false differences."""
    sessions = ScriptedSessions()
    sweep = build(sessions)

    sweep.run(
        [EndpointSpec("GET", "/a"), EndpointSpec("GET", "/b")],
        owner="account24",
        other="account25",
    )

    paths = [path for _, path in sessions.calls]
    assert paths == ["/a", "/a", "/a", "/b", "/b", "/b"]


def test_the_owner_is_probed_first() -> None:
    sessions = ScriptedSessions()
    sweep = build(sessions)

    sweep.run([EndpointSpec("GET", "/a")], owner="account24", other="account25")

    assert sessions.calls[0][0] == "account24"


def test_requests_are_paced_after_the_first() -> None:
    sessions = ScriptedSessions()
    sweep = build(sessions, policy=SweepPolicy(requests_per_minute=30))

    sweep.run([EndpointSpec("GET", "/a")], owner="account24", other="account25")

    naps = sweep.naps  # type: ignore[attr-defined]
    assert naps == [pytest.approx(2.0), pytest.approx(2.0)]


def test_anonymous_can_be_excluded() -> None:
    sessions = ScriptedSessions()
    sweep = build(sessions)

    sweep.run(
        [EndpointSpec("GET", "/a")],
        owner="account24",
        other="account25",
        include_anonymous=False,
    )

    assert all(identity != ANONYMOUS for identity, _ in sessions.calls)


def test_one_failing_endpoint_does_not_abandon_the_rest() -> None:
    sessions = ScriptedSessions(failures={("account24", "/a")})
    sweep = build(sessions)

    report = sweep.run(
        [EndpointSpec("GET", "/a"), EndpointSpec("GET", "/b")],
        owner="account24",
        other="account25",
    )

    assert len(report.outcomes) == 2
    assert report.outcomes[0].error == "target unreachable"
    assert report.outcomes[1].error is None
    assert report.stopped_early is None


def test_persistent_failures_stop_the_sweep() -> None:
    """A target that stops answering should not be hammered for the whole inventory."""
    sessions = ScriptedSessions(
        failures={(identity, "/a") for identity in ("account24", "account25", ANONYMOUS)}
    )
    sweep = build(sessions, policy=SweepPolicy(maximum_consecutive_errors=3))

    report = sweep.run(
        [EndpointSpec("GET", "/a"), EndpointSpec("GET", "/b")],
        owner="account24",
        other="account25",
    )

    assert report.stopped_early == "consecutive_probe_errors"
    assert len(report.outcomes) == 1


def test_a_single_probe_yields_no_verdict() -> None:
    """One observation cannot be a comparison."""
    sessions = ScriptedSessions(failures={("account25", "/a"), (ANONYMOUS, "/a")})
    sweep = build(sessions)

    report = sweep.run(
        [EndpointSpec("GET", "/a")], owner="account24", other="account25"
    )

    assert report.outcomes[0].verdicts == ()


def test_the_plan_size_is_predictable_before_starting() -> None:
    endpoints = [EndpointSpec("GET", f"/web/{index}") for index in range(29)]

    assert probe_plan_size(endpoints, 3) == 87


def test_a_summary_names_each_triggered_rule() -> None:
    sessions = ScriptedSessions(
        responses={
            ("account24", "/web/files/42"): (200, OWNER_DIGEST, 400),
            ("account25", "/web/files/42"): (200, OWNER_DIGEST, 400),
            (ANONYMOUS, "/web/files/42"): (401, DENIED_DIGEST, 40),
        }
    )
    sweep = build(sessions)

    report = sweep.run(
        [EndpointSpec("GET", "/web/files/42")], owner="account24", other="account25"
    )
    lines = summarise(report)

    assert any("horizontal_privilege" in line for line in lines)
    assert all(line.startswith("[TRIGGERED]") for line in lines)
