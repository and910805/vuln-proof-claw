"""Tests for the differential sweep driver."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import UTC, datetime

import pytest

from tests.agent.support import TARGET_HOST
from vuln_proof_claw.agent.authsession import ProbeError
from vuln_proof_claw.agent.differential import ANONYMOUS, OracleRule, ProbeResult, body_digest
from vuln_proof_claw.agent.endpoints import (
    EndpointClassification,
    EndpointRisk,
    ProbeStrategy,
    classify_all,
)
from vuln_proof_claw.agent.sweep import (
    DifferentialSweep,
    EndpointSpec,
    SweepPlan,
    SweepPolicy,
    SweepProber,
    plan_sweep,
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
    strategies: list[ProbeStrategy] = field(default_factory=list)
    authenticated: list[str] = field(default_factory=list)

    def authenticate(self, identity: str, *, at: datetime | None = None) -> None:
        self.authenticated.append(identity)

    def probe(
        self,
        identity: str,
        method: str,
        target: str,
        *,
        strategy: ProbeStrategy = ProbeStrategy.DIRECT,
        at: datetime | None = None,
    ) -> ProbeResult:
        path = target.replace(BASE, "")
        self.calls.append((identity, path))
        self.strategies.append(strategy)
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


def test_a_direct_spec_only_accepts_reads() -> None:
    with pytest.raises(DomainValidationError, match="only read"):
        EndpointSpec(method="POST", path="/web/x")
    with pytest.raises(DomainValidationError, match="absolute"):
        EndpointSpec(method="GET", path="web/x")
    assert EndpointSpec(method="get", path="/web/x").method == "GET"


def test_an_empty_body_spec_only_accepts_post() -> None:
    assert (
        EndpointSpec("post", "/api/getX", ProbeStrategy.EMPTY_BODY).method == "POST"
    )
    with pytest.raises(DomainValidationError, match="POST only"):
        EndpointSpec("GET", "/api/getX", ProbeStrategy.EMPTY_BODY)


def test_a_refused_endpoint_cannot_become_a_spec() -> None:
    """The refusal has to bind here too, or a caller could route around the classifier."""
    with pytest.raises(DomainValidationError, match="never swept"):
        EndpointSpec("POST", "/api/setDeviceSecureWipe", ProbeStrategy.REFUSE)


def test_the_strategy_travels_with_each_endpoint() -> None:
    """Most APIs worth testing expose their reads over POST; the sweep must follow."""
    sessions = ScriptedSessions()
    sweep = build(sessions)

    sweep.run(
        [
            EndpointSpec("GET", "/a"),
            EndpointSpec("POST", "/api/getUserMenuList", ProbeStrategy.EMPTY_BODY),
        ],
        owner="account24",
        include_anonymous=False,
    )

    assert sessions.strategies == [ProbeStrategy.DIRECT, ProbeStrategy.EMPTY_BODY]


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


def test_a_single_probe_yields_no_comparison_verdict() -> None:
    """One observation cannot be a comparison, and the comparison rules must say so."""
    sessions = ScriptedSessions(failures={("account25", "/a"), (ANONYMOUS, "/a")})
    sweep = build(sessions)

    report = sweep.run(
        [EndpointSpec("GET", "/a")], owner="account24", other="account25"
    )

    assert all(not verdict.triggered for verdict in report.outcomes[0].verdicts)


def test_an_anonymous_only_sweep_still_judges_authentication() -> None:
    """Without credentials this is the only rule that can fire — and it is the one
    that matters most, so the sweep must not stay silent for want of a comparison."""
    sessions = ScriptedSessions(
        responses={(ANONYMOUS, "/api/getCompanyDisplay"): (200, OWNER_DIGEST, 94)}
    )
    sweep = build(sessions)

    report = sweep.run([EndpointSpec("GET", "/api/getCompanyDisplay")], owner=ANONYMOUS)

    rules = [verdict.rule for verdict in report.triggered[0].triggered]
    assert rules == [OracleRule.MISSING_AUTHENTICATION]
    assert report.requests_sent == 1


def test_an_anonymous_only_sweep_respects_a_correct_refusal() -> None:
    sessions = ScriptedSessions(
        responses={(ANONYMOUS, "/api/getCompanyDisplay"): (401, DENIED_DIGEST, 40)}
    )
    sweep = build(sessions)

    report = sweep.run([EndpointSpec("GET", "/api/getCompanyDisplay")], owner=ANONYMOUS)

    assert report.triggered == ()


def test_the_plan_size_is_predictable_before_starting() -> None:
    endpoints = [EndpointSpec("GET", f"/web/{index}") for index in range(29)]

    assert probe_plan_size(endpoints, 3) == 87


INVENTORY: tuple[tuple[str, str], ...] = (
    ("GET", "/api/getCompanyDisplay"),
    ("POST", "/api/getUserMenuList"),
    ("POST", "/api/setDeviceMessage"),
    ("POST", "/api/setDeviceSecureWipe"),
    ("GET", "/api/companies/{param}/members"),
)


def reasons(plan: SweepPlan) -> dict[str, str]:
    return dict(plan.withheld)


def test_a_destructive_endpoint_is_never_planned() -> None:
    plan = plan_sweep(classify_all(INVENTORY), limit=10)

    assert all("SecureWipe" not in spec.path for spec in plan.endpoints)
    assert reasons(plan)["/api/setDeviceSecureWipe"] == "destructive"


def test_a_mutating_endpoint_waits_for_a_human() -> None:
    """An empty-body POST to setX is still a write attempt; L1 does not cover it."""
    plan = plan_sweep(classify_all(INVENTORY), limit=10)

    assert reasons(plan)["/api/setDeviceMessage"] == "mutating_requires_approval"


def test_an_operator_can_opt_into_mutating_endpoints() -> None:
    plan = plan_sweep(classify_all(INVENTORY), limit=10, include_mutating=True)

    assert any(spec.path == "/api/setDeviceMessage" for spec in plan.endpoints)


def test_a_read_exposed_over_post_is_planned_with_an_empty_body() -> None:
    plan = plan_sweep(classify_all(INVENTORY), limit=10)
    by_path = {spec.path: spec for spec in plan.endpoints}

    assert by_path["/api/getUserMenuList"].strategy is ProbeStrategy.EMPTY_BODY
    assert by_path["/api/getCompanyDisplay"].strategy is ProbeStrategy.DIRECT


def test_a_placeholder_in_a_path_segment_is_not_probed_literally() -> None:
    """A placeholder would answer 404 and produce a confident verdict about nothing."""
    plan = plan_sweep(classify_all(INVENTORY), limit=10)

    assert (
        reasons(plan)["/api/companies/{param}/members"]
        == "parameterised_path_needs_an_identifier"
    )


def test_a_placeholder_in_the_query_is_dropped_and_the_path_probed() -> None:
    """Omitting a required parameter is how you learn which layer does the rejecting.

    This is the case the IT-08 authentication gap was found through: the server routes
    and answers the bare path, and what it answers says whether authentication ran.
    """
    plan = plan_sweep(
        classify_all((("GET", "/api/getCompanyDisplay?adminUuid={param}"),)), limit=10
    )

    assert [spec.path for spec in plan.endpoints] == ["/api/getCompanyDisplay"]
    assert plan.withheld == ()


def test_the_plan_stops_at_the_request_budget() -> None:
    plan = plan_sweep(classify_all(INVENTORY), limit=1)

    assert len(plan) == 1
    assert "request_budget" in reasons(plan).values()


def test_no_budget_plans_nothing() -> None:
    plan = plan_sweep(classify_all(INVENTORY), limit=0)

    assert plan.endpoints == ()


def test_a_classification_the_spec_refuses_is_withheld_not_raised() -> None:
    """Observed live: a classification two of our own rules disagreed about took the
    cycle down nine times running.

    A disagreement between the classifier and the spec is not a reason to abandon the
    other two hundred endpoints — it is withheld, with the refusal attached so the
    disagreement is visible.
    """
    impossible = EndpointClassification(
        method="DELETE",
        path="/web/vans/blacklist",
        risk=EndpointRisk.READ,
        strategy=ProbeStrategy.EMPTY_BODY,
        reason="a classification the spec will not accept",
    )
    alongside = classify_all((("GET", "/api/getStatus"),))

    plan = plan_sweep((impossible, *alongside), limit=10)

    assert [spec.path for spec in plan.endpoints] == ["/api/getStatus"]
    assert any("not probeable" in reason for _, reason in plan.withheld)


def test_a_negative_budget_is_refused() -> None:
    with pytest.raises(DomainValidationError, match="not be negative"):
        plan_sweep(classify_all(INVENTORY), limit=-1)


def test_the_prober_authenticates_once_across_cycles() -> None:
    """Re-authenticating every cycle would spend the budget on logins."""
    sessions = ScriptedSessions()
    prober = SweepProber(sweep=build(sessions), owner="account24", other="account25")

    prober.probe([EndpointSpec("GET", "/a")], at=NOW)
    prober.probe([EndpointSpec("GET", "/a")], at=NOW)

    assert sessions.authenticated == ["account24", "account25", ANONYMOUS]


def test_the_prober_reports_what_it_actually_sent() -> None:
    """A sweep that stopped early must not charge the budget for its whole plan."""
    sessions = ScriptedSessions(
        failures={(identity, "/a") for identity in ("account24", "account25", ANONYMOUS)}
    )
    sweep = build(sessions, policy=SweepPolicy(maximum_consecutive_errors=3))
    prober = SweepProber(sweep=sweep, owner="account24", other="account25")

    outcome = prober.probe(
        [EndpointSpec("GET", "/a"), EndpointSpec("GET", "/b")], at=NOW
    )

    assert outcome.requests_sent == 3
    assert outcome.stopped_early == "consecutive_probe_errors"


def test_the_prober_returns_every_verdict_for_recording() -> None:
    sessions = ScriptedSessions(
        responses={
            ("account24", "/web/files/42"): (200, OWNER_DIGEST, 400),
            ("account25", "/web/files/42"): (200, OWNER_DIGEST, 400),
            (ANONYMOUS, "/web/files/42"): (401, DENIED_DIGEST, 40),
        }
    )
    prober = SweepProber(sweep=build(sessions), owner="account24", other="account25")

    outcome = prober.probe([EndpointSpec("GET", "/web/files/42")], at=NOW)

    triggered = [verdict for verdict in outcome.verdicts if verdict.triggered]
    assert any(verdict.rule is OracleRule.HORIZONTAL_PRIVILEGE for verdict in triggered)


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
