"""Tests for scope-enforced SPA reconnaissance."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import UTC, datetime

import pytest

from vuln_proof_claw.agent.authsession import ProbeLimits, RawResponse
from vuln_proof_claw.agent.endpoints import EndpointRisk
from vuln_proof_claw.agent.recon import SpaReconnaissance
from vuln_proof_claw.policy.scope import EngagementScope

NOW = datetime(2026, 10, 5, 12, 0, tzinfo=UTC)
HOST = "admyn.example.com"
BASE = f"https://{HOST}/"

SCOPE = EngagementScope.create(
    allowed_hostnames=(HOST,), allowed_ports=(443,), allowed_schemes=("https",)
)

PAGE = b"""<!doctype html><html><head>
<script type="module" crossorigin src="/assets/index-abc.js"></script>
<link rel="modulepreload" crossorigin href="/assets/vendor-xyz.js">
<link rel="stylesheet" href="/assets/index.css">
</head><body><div id="app"></div></body></html>"""

APP_BUNDLE = b"""
function a(e){return r({url:"/api/getUserMenuList",method:"post"})}
function b(e){return r({url:"/api/setDeviceSecureWipe",method:"post"})}
function c(e){return n.get(`/api/companies/${e}/members`)}
"""
VENDOR_BUNDLE = b"/* third party, no endpoints */"


@dataclass
class StubTransport:
    """Serves canned responses and records every URL requested."""

    responses: dict[str, tuple[int, bytes]] = field(default_factory=dict)
    requested: list[str] = field(default_factory=list)
    fail_on: set[str] = field(default_factory=set)

    def send(
        self,
        method: str,
        target: str,
        *,
        headers: tuple[tuple[str, str], ...],
        body: str | None,
        limits: ProbeLimits,
    ) -> RawResponse:
        self.requested.append(target)
        if target in self.fail_on:
            raise OSError("connection reset")
        status, payload = self.responses.get(target, (404, b""))
        return RawResponse(status, (("content-type", "text/plain"),), payload)


def build(
    transport: StubTransport, *, maximum_assets: int = 8
) -> tuple[SpaReconnaissance, list[float]]:
    naps: list[float] = []
    recon = SpaReconnaissance(
        transport=transport,  # type: ignore[arg-type]
        scope=SCOPE,
        base_url=BASE,
        maximum_assets=maximum_assets,
        pacer=naps.append,
    )
    return (recon, naps)


def default_transport() -> StubTransport:
    return StubTransport(
        responses={
            BASE: (200, PAGE),
            f"{BASE}assets/index-abc.js": (200, APP_BUNDLE),
            f"{BASE}assets/vendor-xyz.js": (200, VENDOR_BUNDLE),
        }
    )


def test_the_page_and_its_scripts_are_fetched() -> None:
    transport = default_transport()
    recon, _ = build(transport)

    result = recon.discover(at=NOW)

    assert len(result.assets) == 2
    assert f"{BASE}assets/index-abc.js" in transport.requested
    assert f"{BASE}assets/vendor-xyz.js" in transport.requested


def test_stylesheets_are_not_fetched() -> None:
    transport = default_transport()
    recon, _ = build(transport)

    recon.discover(at=NOW)

    assert all(not url.endswith(".css") for url in transport.requested)


def test_the_api_inventory_is_recovered_and_classified() -> None:
    recon, _ = build(default_transport())

    result = recon.discover(at=NOW)
    paths = {call.path for call in result.calls}

    assert "/api/getUserMenuList" in paths
    assert "/api/setDeviceSecureWipe" in paths
    assert "/api/companies/{param}/members" in paths
    assert len(result.classifications) == len(result.calls)


def test_destructive_endpoints_are_separated_from_probeable_ones() -> None:
    recon, _ = build(default_transport())

    result = recon.discover(at=NOW)

    assert {item.path for item in result.held_back} == {"/api/setDeviceSecureWipe"}
    assert all(
        item.risk is not EndpointRisk.DESTRUCTIVE for item in result.probeable
    )


def test_requests_are_paced_after_the_first() -> None:
    recon, naps = build(default_transport())

    recon.discover(at=NOW)

    assert naps == [pytest.approx(2.0), pytest.approx(2.0)]


def test_every_request_sent_is_counted() -> None:
    """Bounded is not the same as unaccounted; the ledger needs the number."""
    transport = default_transport()
    recon, _ = build(transport)

    result = recon.discover(at=NOW)

    assert result.requests_sent == len(transport.requested)
    assert result.requests_sent == 3  # the page and its two scripts


def test_a_failed_fetch_is_still_counted() -> None:
    """It reached the target; whether it answered does not change that."""
    transport = default_transport()
    transport.fail_on = {f"{BASE}assets/vendor-xyz.js"}
    recon, _ = build(transport)

    result = recon.discover(at=NOW)

    assert len(result.assets) == 1
    assert result.requests_sent == 3


def test_an_asset_refused_by_scope_is_not_counted() -> None:
    """Nothing left the machine, so nothing is charged."""
    page = PAGE.replace(b'src="/assets/index-abc.js"', b'src="https://evil.test/x.js"')
    transport = StubTransport(responses={BASE: (200, page)})
    recon, _ = build(transport)

    result = recon.discover(at=NOW)

    assert result.requests_sent == len(transport.requested)


def test_an_unreachable_entry_page_still_reports_its_request() -> None:
    recon, _ = build(StubTransport())

    assert recon.discover(at=NOW).requests_sent == 1


def test_an_out_of_scope_asset_is_never_fetched() -> None:
    page = PAGE.replace(b'src="/assets/index-abc.js"', b'src="https://evil.test/x.js"')
    transport = StubTransport(responses={BASE: (200, page)})
    recon, _ = build(transport)

    result = recon.discover(at=NOW)

    assert all("evil.test" not in url for url in transport.requested)
    assert result.calls == ()


def test_an_unreachable_asset_does_not_end_reconnaissance() -> None:
    transport = default_transport()
    transport.fail_on = {f"{BASE}assets/vendor-xyz.js"}
    recon, _ = build(transport)

    result = recon.discover(at=NOW)

    assert len(result.assets) == 1
    assert any("vendor-xyz" in error for error in result.errors)
    assert result.calls  # the application bundle was still parsed


def test_an_unreachable_entry_page_yields_an_empty_result() -> None:
    recon, _ = build(StubTransport())

    result = recon.discover(at=NOW)

    assert result.assets == ()
    assert result.calls == ()
    assert result.errors == ("entry page could not be retrieved",)


def test_the_asset_budget_is_respected() -> None:
    transport = default_transport()
    recon, _ = build(transport, maximum_assets=1)

    result = recon.discover(at=NOW)

    assert len(result.assets) == 1


def test_the_application_bundle_is_fetched_before_vendor_code() -> None:
    """With a bounded budget, order decides what is found."""
    transport = default_transport()
    recon, _ = build(transport, maximum_assets=1)

    recon.discover(at=NOW)

    assert transport.requested[1].endswith("index-abc.js")


def test_the_surface_digest_changes_when_a_bundle_changes() -> None:
    first = default_transport()
    recon_a, _ = build(first)
    before = recon_a.discover(at=NOW).surface_digest

    second = default_transport()
    second.responses[f"{BASE}assets/index-abc.js"] = (200, APP_BUNDLE + b"\n// redeployed")
    recon_b, _ = build(second)
    after = recon_b.discover(at=NOW).surface_digest

    assert before != after


def test_the_surface_digest_is_stable_across_identical_passes() -> None:
    recon_a, _ = build(default_transport())
    recon_b, _ = build(default_transport())

    assert recon_a.discover(at=NOW).surface_digest == recon_b.discover(at=NOW).surface_digest
