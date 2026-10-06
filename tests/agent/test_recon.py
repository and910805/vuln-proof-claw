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
    redirects: dict[str, str] = field(default_factory=dict)
    sent_headers: dict[str, tuple[tuple[str, str], ...]] = field(default_factory=dict)

    def headers_for(self, url: str) -> tuple[tuple[str, str], ...] | None:
        return self.sent_headers.get(url)

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
        self.sent_headers[target] = headers
        if target in self.fail_on:
            raise OSError("connection reset")
        if target in self.redirects:
            return RawResponse(302, (("location", self.redirects[target]),), b"")
        status, payload = self.responses.get(target, (404, b""))
        return RawResponse(status, (("content-type", "text/plain"),), payload)


def build(
    transport: StubTransport, *, maximum_assets: int = 8, maximum_pages: int = 0
) -> tuple[SpaReconnaissance, list[float]]:
    naps: list[float] = []
    recon = SpaReconnaissance(
        transport=transport,  # type: ignore[arg-type]
        scope=SCOPE,
        base_url=BASE,
        maximum_assets=maximum_assets,
        maximum_pages=maximum_pages,
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


CDN = "cdn.example.net"
CDN_PAGE = PAGE.replace(
    b'src="/assets/index-abc.js"', f'src="https://{CDN}/packs/app.js"'.encode()
)


def test_an_asset_on_a_named_origin_is_read() -> None:
    """The code describing an in-scope API often sits on an out-of-scope CDN."""
    transport = StubTransport(
        responses={BASE: (200, CDN_PAGE), f"https://{CDN}/packs/app.js": (200, APP_BUNDLE)}
    )
    recon = SpaReconnaissance(
        transport=transport,  # type: ignore[arg-type]
        scope=SCOPE,
        base_url=BASE,
        asset_origins=frozenset({CDN}),
        pacer=lambda _: None,
    )

    result = recon.discover(at=NOW)

    assert "/api/getUserMenuList" in {call.path for call in result.calls}


def test_an_origin_not_named_is_still_refused() -> None:
    transport = StubTransport(responses={BASE: (200, CDN_PAGE)})
    recon = SpaReconnaissance(
        transport=transport,  # type: ignore[arg-type]
        scope=SCOPE,
        base_url=BASE,
        asset_origins=frozenset({"other.example.net"}),
        pacer=lambda _: None,
    )

    result = recon.discover(at=NOW)

    assert all(CDN not in url for url in transport.requested)
    assert result.calls == ()


def test_an_asset_origin_cannot_supply_the_entry_page() -> None:
    """The application being examined must always be one the engagement authorizes."""
    transport = StubTransport(responses={f"https://{CDN}/": (200, PAGE)})
    recon = SpaReconnaissance(
        transport=transport,  # type: ignore[arg-type]
        scope=SCOPE,
        base_url=f"https://{CDN}/",
        asset_origins=frozenset({CDN}),
        pacer=lambda _: None,
    )

    result = recon.discover(at=NOW)

    assert transport.requested == []
    assert "refused by scope" in result.errors[0]


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


def test_an_unreachable_entry_page_says_why() -> None:
    """'could not be retrieved' and 'HTTP 302 to /tw/' send an operator to very
    different places, and only one of them is a dead end."""
    recon, _ = build(StubTransport())

    result = recon.discover(at=NOW)

    assert result.assets == ()
    assert result.calls == ()
    assert result.errors == ("entry page not retrieved — HTTP 404",)


def test_a_transport_failure_is_named_in_the_error() -> None:
    transport = default_transport()
    transport.fail_on = {BASE}
    recon, _ = build(transport)

    result = recon.discover(at=NOW)

    assert "OSError" in result.errors[0]
    assert "connection reset" in result.errors[0]


def test_an_entry_redirect_is_followed_inside_scope() -> None:
    """An entry page commonly 301s to a locale prefix; that is not a dead end."""
    transport = StubTransport(
        responses={
            f"{BASE}tw/": (200, PAGE),
            f"{BASE}assets/index-abc.js": (200, APP_BUNDLE),
            f"{BASE}assets/vendor-xyz.js": (200, VENDOR_BUNDLE),
        },
        redirects={BASE: f"{BASE}tw/"},
    )
    recon, _ = build(transport)

    result = recon.discover(at=NOW)

    assert {call.path for call in result.calls} >= {"/api/getUserMenuList"}
    assert f"{BASE}tw/" in transport.requested


def test_a_redirect_out_of_scope_is_not_followed() -> None:
    """The transport refuses to follow one itself; re-pointing must not bypass that."""
    transport = StubTransport(redirects={BASE: "https://evil.test/"})
    recon, _ = build(transport)

    result = recon.discover(at=NOW)

    assert all("evil.test" not in url for url in transport.requested)
    assert "refused by scope" in result.errors[0]


def test_a_redirect_loop_ends() -> None:
    transport = StubTransport(redirects={BASE: BASE})
    recon, _ = build(transport)

    result = recon.discover(at=NOW)

    assert "redirects" in result.errors[0]


def test_a_refused_asset_does_not_consume_the_budget() -> None:
    """A page may reference a third-party reporter before its own code.

    Refusing that costs no request, so it must not cost a slot either — otherwise the
    budget is spent on scripts that were never read.
    """
    page = PAGE.replace(
        b'<script type="module" crossorigin src="/assets/index-abc.js"></script>',
        b'<script src="https://tracker.test/a.js"></script>'
        b'<script src="https://tracker.test/b.js"></script>'
        b'<script type="module" crossorigin src="/assets/index-abc.js"></script>',
    )
    transport = StubTransport(
        responses={BASE: (200, page), f"{BASE}assets/index-abc.js": (200, APP_BUNDLE)}
    )
    recon, _ = build(transport, maximum_assets=1)

    result = recon.discover(at=NOW)

    assert len(result.assets) == 1
    assert "/api/getUserMenuList" in {call.path for call in result.calls}


def test_a_split_build_chunk_outranks_a_third_party_script() -> None:
    """shared~<hash>.chunk.js is where a split build keeps the API layer."""
    ordered = SpaReconnaissance._prioritise(
        (
            "https://browser.sentry-cdn.com/7/bundle.min.js",
            "https://cdn.test/packs/js/shared~38c579ec-439cff9e.chunk.js",
        )
    )

    assert "shared~" in ordered[0]


def test_a_named_chunk_outranks_a_numbered_one() -> None:
    """Observed on a live target: the API layer sat in commons.<hash>.chunk.js.

    Every file in a split build ends in .chunk.js, so treating that suffix as a hint
    matched all of them and the ranking stopped separating anything — the budget went
    to 27.<hash>.chunk.js and the one worth reading was never fetched.
    """
    ordered = SpaReconnaissance._prioritise(
        (
            "dist/27.95dfb3a6360c85380083.chunk.js",
            "dist/140.322b19ae950c8b1c2cc6.chunk.js",
            "dist/commons.3b25d8db336b9de057d4.chunk.js",
        )
    )

    assert "commons" in ordered[0]


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


def test_discovery_looks_through_the_supplied_session() -> None:
    """On an application behind a login, anonymous discovery sees the login page."""
    transport = default_transport()
    recon = SpaReconnaissance(
        transport=transport,  # type: ignore[arg-type]
        scope=SCOPE,
        base_url=BASE,
        session_headers=lambda: (("cookie", "session=abc123"),),
        pacer=lambda _: None,
    )

    recon.discover(at=NOW)

    sent = transport.headers_for(BASE)
    assert sent is not None
    assert ("cookie", "session=abc123") in sent


def test_a_session_cookie_is_withheld_from_an_asset_origin() -> None:
    """A CDN is a third party; the application's session has no business there."""
    page = PAGE.replace(
        b'src="/assets/index-abc.js"', b'src="https://cdn.example.net/app.js"'
    )
    transport = StubTransport(
        responses={
            BASE: (200, page),
            "https://cdn.example.net/app.js": (200, APP_BUNDLE),
        }
    )
    recon = SpaReconnaissance(
        transport=transport,  # type: ignore[arg-type]
        scope=SCOPE,
        base_url=BASE,
        asset_origins=frozenset({"cdn.example.net"}),
        session_headers=lambda: (("cookie", "session=abc123"),),
        pacer=lambda _: None,
    )

    recon.discover(at=NOW)

    sent = transport.headers_for("https://cdn.example.net/app.js")
    assert sent is not None
    assert all(name != "cookie" for name, _ in sent)


def test_a_server_rendered_page_still_yields_its_surface() -> None:
    """Observed on IT-01 and IT-02: PHP applications describe no API in JavaScript.

    Reporting an empty inventory for a target that plainly has one was the gap; the
    markup is where a server-rendered application's surface actually lives.
    """
    page = (
        b"<html><body>"
        b'<form method="POST" action="/index.php"></form>'
        b'<a href="/reports.php?id=1">r</a>'
        b"</body></html>"
    )
    transport = StubTransport(responses={BASE: (200, page)})
    recon, _ = build(transport)

    result = recon.discover(at=NOW)
    found = {(item.method, item.path) for item in result.classifications}

    assert ("POST", "/index.php") in found
    assert ("GET", "/reports.php?id=1") in found


def test_markup_endpoints_do_not_displace_the_api_a_bundle_describes() -> None:
    """A single-page application keeps giving its JavaScript-described API."""
    recon, _ = build(default_transport())

    result = recon.discover(at=NOW)
    found = {item.path for item in result.classifications}

    assert "/api/getUserMenuList" in found


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


SERVER_RENDERED = """
<html><body>
  <a href="/admin/users">Users</a>
  <a href="/admin/policy">Policy</a>
  <a href="https://elsewhere.test/docs">Docs</a>
  <a href="/admin/users?page=2">Page 2</a>
  <form method="post" action="/admin/login"><input name="u"></form>
</body></html>
"""

USERS_PAGE = """
<html><body>
  <a href="/admin/users/export">Export</a>
  <form method="post" action="/admin/users/create"><input name="n"></form>
</body></html>
"""

POLICY_PAGE = '<html><body><a href="/admin/policy/rules">Rules</a></body></html>'


def server_rendered_transport() -> StubTransport:
    return StubTransport(
        responses={
            BASE: (200, SERVER_RENDERED.encode()),
            f"{BASE}admin/users": (200, USERS_PAGE.encode()),
            f"{BASE}admin/policy": (200, POLICY_PAGE.encode()),
        }
    )


def test_only_the_entry_page_is_read_when_no_pages_are_allowed() -> None:
    """The previous behaviour, kept reachable: zero means read one page."""
    recon, _ = build(server_rendered_transport(), maximum_pages=0)

    paths = {item.path for item in recon.discover().classifications}

    assert "/admin/users" in paths
    assert "/admin/users/export" not in paths


def test_a_linked_page_contributes_its_own_surface() -> None:
    """One management interface's entry page offered five requests; the pages one
    click behind it offered the rest. Reading only the first reports an application
    as having almost no surface, and a sweep then confirms it."""
    recon, _ = build(server_rendered_transport(), maximum_pages=5)

    paths = {item.path for item in recon.discover().classifications}

    assert {"/admin/users/export", "/admin/users/create", "/admin/policy/rules"} <= paths


def test_the_page_budget_is_a_ceiling() -> None:
    transport = server_rendered_transport()
    recon, _ = build(transport, maximum_pages=1)

    recon.discover()

    followed = [url for url in transport.requested if url.startswith(f"{BASE}admin/")]
    assert len(followed) == 1


def test_another_site_is_never_followed() -> None:
    """An anchor to somebody else's host is somebody else's surface, and testing it
    is the one thing the engagement forbids outright."""
    transport = server_rendered_transport()
    recon, _ = build(transport, maximum_pages=5)

    recon.discover()

    assert all("elsewhere.test" not in url for url in transport.requested)


def test_a_form_target_is_not_followed() -> None:
    """A form's action is a state change until something proves otherwise, and this
    is reconnaissance."""
    transport = server_rendered_transport()
    recon, _ = build(transport, maximum_pages=5)

    recon.discover()

    assert f"{BASE}admin/login" not in transport.requested


def test_a_linked_page_that_cannot_be_read_costs_only_that_page() -> None:
    transport = StubTransport(
        responses={
            BASE: (200, SERVER_RENDERED.encode()),
            f"{BASE}admin/policy": (200, POLICY_PAGE.encode()),
        }
    )
    recon, _ = build(transport, maximum_pages=5)

    result = recon.discover()

    assert any("linked page not retrieved" in error for error in result.errors)
    assert "/admin/policy/rules" in {item.path for item in result.classifications}
