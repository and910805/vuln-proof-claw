"""Tests for the proxy-free, DNS-pinned passive HTTP transport."""

from __future__ import annotations

import ssl
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any

import pytest

from vuln_proof_claw.domain.identifiers import ActionId
from vuln_proof_claw.execution.http_capture import (
    CaptureTransportError,
    HttpCaptureLimits,
    HttpCaptureRequest,
)
from vuln_proof_claw.execution.pinned_http import PinnedHttpTransport
from vuln_proof_claw.policy.scope import EngagementScope


class FakeResponse:
    status = 200

    def __init__(self, body: bytes = b"ok", headers: tuple[tuple[str, str], ...] = ()) -> None:
        self._body = body
        self._headers = headers

    def getheader(self, name: str) -> str | None:
        for key, value in self._headers:
            if key.lower() == name.lower():
                return value
        return None

    def getheaders(self) -> list[tuple[str, str]]:
        return list(self._headers)

    def read(self, amount: int) -> bytes:
        return self._body[:amount]


class FakeConnection:
    def __init__(self, response: FakeResponse) -> None:
        self.response = response
        self.request_args: tuple[Any, ...] | None = None
        self.closed = False

    def request(self, *args: Any, **kwargs: Any) -> None:
        self.request_args = (*args, kwargs)

    def getresponse(self) -> FakeResponse:
        return self.response

    def close(self) -> None:
        self.closed = True


def scope(*, cidrs: tuple[str, ...] = ()) -> EngagementScope:
    return EngagementScope.create(
        allowed_hostnames=("example.test",),
        allowed_cidrs=cidrs,
        allowed_ports=(443,),
        allowed_schemes=("https",),
    )


def request() -> HttpCaptureRequest:
    return HttpCaptureRequest(
        action_id=ActionId("00000000-0000-7000-8000-000000000001"),
        method="GET",
        target="https://example.test/",
        headers=(("Accept", "text/html"),),
    )


def test_transport_pins_public_dns_streams_bounded_body_and_preserves_duplicate_headers() -> None:
    connection = FakeConnection(
        FakeResponse(
            b"response",
            (("Set-Cookie", "a=1; Secure"), ("Set-Cookie", "b=2; HttpOnly")),
        )
    )
    captured: list[tuple[object, ...]] = []

    def factory(*args: object) -> FakeConnection:
        captured.append(args)
        return connection

    transport = PinnedHttpTransport(
        scope(),
        resolver=lambda _host, _port: ("93.184.216.34",),
        ssl_context=ssl.create_default_context(),
        connection_factory=factory,
    )
    response = transport.send(request(), HttpCaptureLimits(max_response_bytes=32))

    assert response.body == b"response"
    assert response.headers == (
        ("set-cookie", "a=1; Secure"),
        ("set-cookie", "b=2; HttpOnly"),
    )
    assert captured[0][2] == "93.184.216.34"
    assert connection.request_args is not None
    assert connection.request_args[0:2] == ("GET", "/")
    assert connection.closed


@pytest.mark.parametrize(
    ("addresses", "error_code"),
    [
        ((), "dns_resolution_empty"),
        (("not-an-ip",), "dns_resolution_invalid"),
        (("127.0.0.1",), "resolved_address_not_public"),
        (("93.184.216.34", "127.0.0.1"), "resolved_address_not_public"),
    ],
)
def test_transport_rejects_empty_invalid_private_and_mixed_dns(
    addresses: tuple[str, ...], error_code: str
) -> None:
    transport = PinnedHttpTransport(scope(), resolver=lambda _host, _port: addresses)

    with pytest.raises(CaptureTransportError, match=error_code):
        transport.send(request(), HttpCaptureLimits())


def test_transport_allows_private_address_only_when_cidr_is_explicitly_scoped() -> None:
    connection = FakeConnection(FakeResponse())
    transport = PinnedHttpTransport(
        scope(cidrs=("10.20.30.0/24",)),
        resolver=lambda _host, _port: ("10.20.30.40",),
        connection_factory=lambda *_args: connection,
    )

    assert transport.send(request(), HttpCaptureLimits()).status_code == 200


def test_transport_allows_private_address_when_allow_private_is_enabled() -> None:
    connection = FakeConnection(FakeResponse())
    transport = PinnedHttpTransport(
        scope(),
        resolver=lambda _host, _port: ("127.0.0.1",),
        connection_factory=lambda *_args: connection,
        allow_private=True,
    )

    assert transport.send(request(), HttpCaptureLimits()).status_code == 200


def test_transport_still_denies_private_address_by_default() -> None:
    transport = PinnedHttpTransport(scope(), resolver=lambda _host, _port: ("127.0.0.1",))

    with pytest.raises(CaptureTransportError, match="resolved_address_not_public"):
        transport.send(request(), HttpCaptureLimits())


def test_transport_rejects_denied_address_and_oversized_content() -> None:
    denied_scope = EngagementScope.create(
        allowed_hostnames=("example.test",),
        allowed_ports=(443,),
        denied_cidrs=("93.184.216.0/24",),
    )
    denied = PinnedHttpTransport(
        denied_scope,
        resolver=lambda _host, _port: ("93.184.216.34",),
    )
    with pytest.raises(CaptureTransportError, match="resolved_address_denied"):
        denied.send(request(), HttpCaptureLimits())

    connection = FakeConnection(FakeResponse(headers=(("Content-Length", "999"),)))
    oversized = PinnedHttpTransport(
        scope(),
        resolver=lambda _host, _port: ("93.184.216.34",),
        connection_factory=lambda *_args: connection,
    )
    with pytest.raises(CaptureTransportError, match="response_body_too_large"):
        oversized.send(request(), HttpCaptureLimits(max_response_bytes=10))


def test_transport_connects_to_an_explicitly_scoped_loopback_server() -> None:
    class Handler(BaseHTTPRequestHandler):
        def do_GET(self) -> None:
            self.send_response(200)
            self.send_header("Content-Type", "text/plain")
            self.end_headers()
            self.wfile.write(b"local integration response")

        def log_message(self, _format: str, *_args: object) -> None:
            return

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        port = server.server_port
        local_scope = EngagementScope.create(
            allowed_cidrs=("127.0.0.1/32",),
            allowed_ports=(port,),
            allowed_schemes=("http",),
        )
        local_request = HttpCaptureRequest(
            action_id=ActionId("00000000-0000-7000-8000-000000000002"),
            method="GET",
            target=f"http://127.0.0.1:{port}/health?full=1",
            headers=(("Accept", "text/plain"),),
        )

        response = PinnedHttpTransport(local_scope).send(
            local_request,
            HttpCaptureLimits(max_response_bytes=128),
        )

        assert response.status_code == 200
        assert response.body == b"local integration response"
        assert response.final_target == local_request.target
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)
