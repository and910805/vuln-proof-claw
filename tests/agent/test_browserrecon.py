"""Tests for recovering a surface through a browser, as a reconnaissance source."""

from __future__ import annotations

from datetime import UTC, datetime

from vuln_proof_claw.agent.browserrecon import BrowserReconnaissance
from vuln_proof_claw.agent.endpoints import EndpointRisk
from vuln_proof_claw.automation.browser import BrowserRunResult, ObservedRequest
from vuln_proof_claw.policy.scope import EngagementScope

NOW = datetime(2026, 10, 5, 13, 0, tzinfo=UTC)
HOST = "10.26.0.40"
BASE = f"https://{HOST}/"

SCOPE = EngagementScope.create(
    allowed_cidrs=("10.26.0.0/24",), allowed_ports=(443,), allowed_schemes=("https",)
)


def observed(method: str, url: str, resource_type: str = "xhr") -> ObservedRequest:
    return ObservedRequest(
        method=method,
        url=url,
        resource_type=resource_type,
        carried_body=method != "GET",
        sent_at=NOW,
    )


class StubRunner:
    """Returns a canned visit, or raises, to test containment."""

    def __init__(
        self,
        *,
        requests: tuple[ObservedRequest, ...] = (),
        blocked: tuple[str, ...] = (),
        explode: Exception | None = None,
    ) -> None:
        self.requests = requests
        self.blocked = blocked
        self.explode = explode
        self.seen: list[object] = []

    async def run(self, request: object) -> BrowserRunResult:
        self.seen.append(request)
        if self.explode is not None:
            raise self.explode
        return BrowserRunResult(
            final_url=f"{BASE}#/login",
            title="RapixEngine",
            status_code=200,
            screenshot=b"",
            blocked_requests=self.blocked,
            observed_requests=self.requests,
        )


def build(runner: StubRunner) -> BrowserReconnaissance:
    return BrowserReconnaissance(
        scope=SCOPE,
        base_url=BASE,
        runner=runner,  # type: ignore[arg-type]
        ignore_https_errors=True,
    )


def test_the_path_that_was_sent_is_the_path_recovered() -> None:
    """Reading a bundle gave /web/x where the client actually sends /api/web/x."""
    recon = build(
        StubRunner(
            requests=(
                observed("GET", f"{BASE}api/web/ui-env-variables/public"),
                observed("POST", f"{BASE}api/web/token"),
            )
        )
    )

    result = recon.discover(at=NOW)
    paths = {item.path for item in result.classifications}

    assert paths == {"/api/web/ui-env-variables/public", "/api/web/token"}


def test_what_the_browser_fetched_to_render_is_not_the_surface() -> None:
    recon = build(
        StubRunner(
            requests=(
                observed("GET", f"{BASE}api/web/clients"),
                observed("GET", f"{BASE}dist/app.css", resource_type="stylesheet"),
                observed("GET", f"{BASE}logo.png", resource_type="image"),
            )
        )
    )

    assert len(recon.discover(at=NOW).classifications) == 1


def test_observations_still_pass_through_the_classifier() -> None:
    """The browser widens what is discovered; it does not widen what may be called."""
    recon = build(
        StubRunner(requests=(observed("DELETE", f"{BASE}api/web/vans/blacklist"),))
    )

    result = recon.discover(at=NOW)

    assert result.classifications[0].risk is EndpointRisk.DESTRUCTIVE
    assert result.held_back


def test_every_request_the_browser_made_is_charged() -> None:
    """The budget answers how hard the host was hit, and a browser hits it."""
    recon = build(
        StubRunner(
            requests=(
                observed("GET", f"{BASE}api/web/a"),
                observed("GET", f"{BASE}app.css", resource_type="stylesheet"),
            )
        )
    )

    result = recon.discover(at=NOW)

    # Two sent, one classified: the stylesheet is not a surface but it was a request.
    assert result.requests_sent == 2
    assert len(result.classifications) == 1


def test_a_blocked_request_is_reported_to_the_operator() -> None:
    """A page reaching outside the engagement is worth knowing even when refused."""
    recon = build(
        StubRunner(
            requests=(observed("GET", f"{BASE}api/web/a"),),
            blocked=("https://cdn.evil.test/x.js",),
        )
    )

    result = recon.discover(at=NOW)

    assert any("out-of-scope" in error for error in result.errors)


def test_a_browser_failure_is_returned_not_raised() -> None:
    """Losing a pass costs a delay; raising would abandon the leads already waiting."""
    recon = build(StubRunner(explode=RuntimeError("browser not installed")))

    result = recon.discover(at=NOW)

    assert result.classifications == ()
    assert "browser not installed" in result.errors[0]


def test_the_visit_stays_inside_the_engagement_scope() -> None:
    runner = StubRunner(requests=())
    build(runner).discover(at=NOW)

    request = runner.seen[0]
    assert HOST in request.allowed_hosts  # type: ignore[attr-defined]
    assert request.allowed_ports == frozenset({443})  # type: ignore[attr-defined]
