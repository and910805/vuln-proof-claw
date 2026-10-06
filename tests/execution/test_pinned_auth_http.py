"""Tests for the DNS-pinned authenticated transport.

The transport widens exactly two things over the capture path — a cookie header and a
POST to one configured login path. These tests exist to prove it widened nothing else.
"""

from __future__ import annotations

import ssl
from dataclasses import dataclass, field
from typing import Any

import pytest

from vuln_proof_claw.agent.authsession import EMPTY_PROBE_BODY, ProbeLimits
from vuln_proof_claw.execution.http_capture import CaptureTransportError
from vuln_proof_claw.execution.pinned_auth_http import (
    PinnedAuthTransport,
    unverified_tls_context,
)
from vuln_proof_claw.policy.scope import EngagementScope

HOST = "api.example.com"
PUBLIC_IP = "93.184.216.34"
INTERNAL_IP = "10.26.0.40"
LOGIN = "/web/login"

SCOPE = EngagementScope.create(
    allowed_hostnames=(HOST,),
    allowed_ports=(443,),
    allowed_schemes=("https",),
)
INTERNAL_SCOPE = EngagementScope.create(
    allowed_hostnames=(HOST,),
    allowed_cidrs=("10.26.0.0/24",),
    allowed_ports=(443,),
    allowed_schemes=("https",),
)


@dataclass
class FakeResponse:
    status: int = 200
    body: bytes = b'{"ok":true}'
    headers: list[tuple[str, str]] = field(default_factory=list)

    def read(self, amount: int) -> bytes:
        return self.body[:amount]

    def getheaders(self) -> list[tuple[str, str]]:
        return self.headers


@dataclass
class FakeConnection:
    response: FakeResponse = field(default_factory=FakeResponse)
    requests: list[dict[str, Any]] = field(default_factory=list)
    closed: bool = False

    def request(
        self,
        method: str,
        url: str,
        *,
        body: bytes | None = None,
        headers: dict[str, str],
    ) -> None:
        self.requests.append(
            {"method": method, "url": url, "body": body, "headers": headers}
        )

    def getresponse(self) -> FakeResponse:
        return self.response

    def close(self) -> None:
        self.closed = True


def build(
    *,
    scope: EngagementScope = SCOPE,
    addresses: tuple[str, ...] = (PUBLIC_IP,),
    connection: FakeConnection | None = None,
    login_path: str | None = LOGIN,
    read_only_origins: frozenset[str] = frozenset(),
) -> tuple[PinnedAuthTransport, FakeConnection]:
    conn = connection or FakeConnection()
    transport = PinnedAuthTransport(
        scope,
        login_path=login_path,
        resolver=lambda hostname, port: addresses,
        connection_factory=lambda *args, **kwargs: conn,
        read_only_origins=read_only_origins,
    )
    return (transport, conn)


def limits() -> ProbeLimits:
    return ProbeLimits(timeout_seconds=5, max_response_bytes=4096)


def test_a_read_is_sent_to_the_pinned_address() -> None:
    transport, conn = build()

    response = transport.send(
        "GET",
        f"https://{HOST}/web/files/42",
        headers=(("accept", "*/*"), ("cookie", "session=abc")),
        body=None,
        limits=limits(),
    )

    assert response.status_code == 200
    assert conn.requests[0]["method"] == "GET"
    assert conn.requests[0]["headers"]["cookie"] == "session=abc"
    assert conn.closed


def test_post_is_allowed_only_on_the_configured_login_path() -> None:
    transport, conn = build()

    transport.send(
        "POST",
        f"https://{HOST}{LOGIN}",
        headers=(("content-type", "application/json"),),
        body='{"username":"a","password":"b"}',
        limits=limits(),
    )

    assert conn.requests[0]["method"] == "POST"
    assert conn.requests[0]["body"] == b'{"username":"a","password":"b"}'


def test_a_post_carrying_data_is_refused_before_connecting() -> None:
    """A planner must not be able to turn a read sweep into a state change."""
    transport, conn = build()

    with pytest.raises(CaptureTransportError, match="post_permitted_only_on_login"):
        transport.send(
            "POST",
            f"https://{HOST}/web/policy-groups/1/clone",
            headers=(),
            body='{"name":"copy"}',
            limits=limits(),
        )

    assert conn.requests == []


def test_an_empty_post_is_permitted_off_the_login_path() -> None:
    """The empty-body probe: a request carrying no data cannot instruct a change."""
    transport, conn = build()

    transport.send(
        "POST",
        f"https://{HOST}/api/getCompanyDisplay",
        headers=(("content-type", "application/json"),),
        body=EMPTY_PROBE_BODY,
        limits=limits(),
    )

    assert len(conn.requests) == 1


@pytest.mark.parametrize("body", ["", " {}", '{"a":1}', "{} ", None])
def test_only_an_exactly_empty_body_passes_the_guard(body: str | None) -> None:
    """Checked byte for byte: anything a caller could smuggle data in is refused."""
    transport, conn = build()

    with pytest.raises(CaptureTransportError):
        transport.send(
            "POST", f"https://{HOST}/api/getX", headers=(), body=body, limits=limits()
        )

    assert conn.requests == []


CDN = "cdn.example.net"


def test_a_named_origin_may_be_read_although_it_is_out_of_scope() -> None:
    """An application's own code often lives on a CDN that is not a target."""
    transport, conn = build(read_only_origins=frozenset({CDN}))

    transport.send(
        "GET", f"https://{CDN}/packs/app.js", headers=(), body=None, limits=limits()
    )

    assert len(conn.requests) == 1


@pytest.mark.parametrize(
    ("method", "body"),
    [("POST", EMPTY_PROBE_BODY), ("HEAD", None)],
    ids=["post", "head"],
)
def test_a_named_origin_permits_nothing_but_a_plain_get(
    method: str, body: str | None
) -> None:
    """Reading a script is not testing the host that served it."""
    transport, conn = build(read_only_origins=frozenset({CDN}))

    with pytest.raises(CaptureTransportError, match="transport_scope_denied"):
        transport.send(
            method, f"https://{CDN}/packs/app.js", headers=(), body=body, limits=limits()
        )

    assert conn.requests == []


def test_an_unnamed_origin_is_still_refused() -> None:
    transport, conn = build(read_only_origins=frozenset({CDN}))

    with pytest.raises(CaptureTransportError, match="transport_scope_denied"):
        transport.send(
            "GET", "https://other.example.net/app.js", headers=(), body=None, limits=limits()
        )

    assert conn.requests == []


def test_an_unverified_context_is_not_the_default() -> None:
    assert ssl.create_default_context().verify_mode is ssl.CERT_REQUIRED

    relaxed = unverified_tls_context()

    assert relaxed.verify_mode is ssl.CERT_NONE
    assert relaxed.check_hostname is False


def test_a_post_with_data_is_refused_when_no_login_path_is_configured() -> None:
    transport, conn = build(login_path=None)

    with pytest.raises(CaptureTransportError):
        transport.send(
            "POST", f"https://{HOST}/anything", headers=(), body="x=1", limits=limits()
        )

    assert conn.requests == []


@pytest.mark.parametrize("method", ["PUT", "DELETE", "PATCH", "OPTIONS", "TRACE"])
def test_other_methods_are_refused(method: str) -> None:
    transport, conn = build()

    with pytest.raises(CaptureTransportError, match="method_not_allowed"):
        transport.send(method, f"https://{HOST}/x", headers=(), body=None, limits=limits())

    assert conn.requests == []


def test_a_body_without_post_is_refused() -> None:
    transport, _ = build()

    with pytest.raises(CaptureTransportError, match="body_permitted_only_on_post"):
        transport.send("GET", f"https://{HOST}/x", headers=(), body="{}", limits=limits())


@pytest.mark.parametrize(
    "header",
    [("authorization", "Bearer x"), ("x-forwarded-for", "1.2.3.4"), ("host", "evil.test")],
)
def test_headers_outside_the_allowlist_are_refused(header: tuple[str, str]) -> None:
    """The allowlist is the reason this transport is safe to point at a real target."""
    transport, conn = build()

    with pytest.raises(CaptureTransportError, match="request_header_not_allowed"):
        transport.send("GET", f"https://{HOST}/x", headers=(header,), body=None, limits=limits())

    assert conn.requests == []


def test_an_out_of_scope_target_never_opens_a_socket() -> None:
    transport, conn = build()

    with pytest.raises(CaptureTransportError, match="transport_scope_denied"):
        transport.send("GET", "https://attacker.test/x", headers=(), body=None, limits=limits())

    assert conn.requests == []


def test_a_private_address_is_refused_unless_the_scope_allows_that_network() -> None:
    refusing, _ = build(addresses=(INTERNAL_IP,))
    with pytest.raises(CaptureTransportError, match="resolved_address_not_public"):
        refusing.send("GET", f"https://{HOST}/x", headers=(), body=None, limits=limits())

    permitting, conn = build(scope=INTERNAL_SCOPE, addresses=(INTERNAL_IP,))
    permitting.send("GET", f"https://{HOST}/x", headers=(), body=None, limits=limits())
    assert len(conn.requests) == 1


def test_a_denied_network_is_refused_even_when_otherwise_allowed() -> None:
    scope = EngagementScope.create(
        allowed_hostnames=(HOST,),
        allowed_cidrs=("10.26.0.0/24",),
        denied_cidrs=(f"{INTERNAL_IP}/32",),
        allowed_ports=(443,),
        allowed_schemes=("https",),
    )
    transport, conn = build(scope=scope, addresses=(INTERNAL_IP,))

    with pytest.raises(CaptureTransportError, match="resolved_address_denied"):
        transport.send("GET", f"https://{HOST}/x", headers=(), body=None, limits=limits())

    assert conn.requests == []


def test_empty_dns_resolution_is_refused() -> None:
    transport, _ = build(addresses=())

    with pytest.raises(CaptureTransportError, match="dns_resolution_empty"):
        transport.send("GET", f"https://{HOST}/x", headers=(), body=None, limits=limits())


def test_an_oversized_response_is_refused() -> None:
    conn = FakeConnection(response=FakeResponse(body=b"a" * 5000))
    transport, _ = build(connection=conn)

    with pytest.raises(CaptureTransportError, match="response_body_too_large"):
        transport.send(
            "GET",
            f"https://{HOST}/x",
            headers=(),
            body=None,
            limits=ProbeLimits(timeout_seconds=5, max_response_bytes=100),
        )


def test_oversized_headers_are_refused() -> None:
    transport, conn = build()
    huge = (("cookie", "a" * 20_000),)

    with pytest.raises(CaptureTransportError, match="request_headers_too_large"):
        transport.send("GET", f"https://{HOST}/x", headers=huge, body=None, limits=limits())

    assert conn.requests == []


def test_response_headers_are_lowercased_for_comparison() -> None:
    conn = FakeConnection(
        response=FakeResponse(headers=[("Set-Cookie", "session=x"), ("Content-Type", "json")])
    )
    transport, _ = build(connection=conn)

    response = transport.send("GET", f"https://{HOST}/x", headers=(), body=None, limits=limits())

    assert dict(response.headers) == {"set-cookie": "session=x", "content-type": "json"}


def test_a_transport_failure_is_reported_safely() -> None:
    class Exploding(FakeConnection):
        def getresponse(self) -> FakeResponse:
            raise OSError("connection reset by peer")

    transport, _ = build(connection=Exploding())

    with pytest.raises(CaptureTransportError, match="transport_request_failed"):
        transport.send("GET", f"https://{HOST}/x", headers=(), body=None, limits=limits())
