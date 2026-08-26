"""Tests for the proxy-free, DNS-pinned passive HTTP transport."""

from __future__ import annotations

import http.client
import socket
import ssl
import threading
from contextlib import closing
from datetime import UTC, datetime
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any, cast

import pytest

from vuln_proof_claw.domain.identifiers import ActionId
from vuln_proof_claw.execution.http_capture import (
    CaptureTransportError,
    HttpCaptureLimits,
    HttpCaptureRequest,
)
from vuln_proof_claw.execution.pinned_http import (
    PinnedHttpTransport,
    _PinnedHttpsConnection,
    system_resolver,
)
from vuln_proof_claw.policy.scope import EngagementScope


class FakeResponse:
    status = 200

    def __init__(self, body: bytes = b"ok", headers: tuple[tuple[str, str], ...] = ()) -> None:
        self._body = body
        self._headers = headers
        self.reads: list[int] = []

    def getheader(self, name: str) -> str | None:
        for key, value in self._headers:
            if key.lower() == name.lower():
                return value
        return None

    def getheaders(self) -> list[tuple[str, str]]:
        return list(self._headers)

    def read(self, amount: int) -> bytes:
        self.reads.append(amount)
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


def request_to(target: str) -> HttpCaptureRequest:
    return HttpCaptureRequest(
        action_id=ActionId("00000000-0000-7000-8000-000000000003"),
        method="GET",
        target=target,
        headers=(("Accept", "text/html"),),
    )


class FailingConnection(FakeConnection):
    """Connection that fails the way a real socket does, once the request is on the wire."""

    def __init__(self, failure: Exception) -> None:
        super().__init__(FakeResponse())
        self.failure = failure

    def getresponse(self) -> FakeResponse:
        raise self.failure


class StubSslContext:
    """Records the identity TLS was asked to verify, and can refuse the handshake."""

    def __init__(self, *, failure: Exception | None = None) -> None:
        self.failure = failure
        self.server_hostnames: list[str | None] = []
        self.wrapped = object()

    def wrap_socket(self, sock: object, *, server_hostname: str | None = None) -> object:
        self.server_hostnames.append(server_hostname)
        if self.failure is not None:
            raise self.failure
        return self.wrapped


class RecordingSocket:
    """Stands in for the raw TCP socket so the test can see whether it was closed."""

    def __init__(self) -> None:
        self.closed = False

    def close(self) -> None:
        self.closed = True


def pin_socket(
    monkeypatch: pytest.MonkeyPatch,
    recorder: RecordingSocket,
) -> list[tuple[str, int]]:
    """Replace the TCP layer and return the list of addresses actually connected to."""
    attempts: list[tuple[str, int]] = []

    def fake_create_connection(
        address: tuple[str, int],
        timeout: float | None = None,
    ) -> RecordingSocket:
        attempts.append(address)
        return recorder

    monkeypatch.setattr(socket, "create_connection", fake_create_connection)
    return attempts


def refuse_resolution(hostname: str, port: int) -> tuple[str, ...]:
    raise AssertionError("scope must be evaluated before any DNS lookup")


def refuse_connection(*_args: object) -> FakeConnection:
    raise AssertionError("scope must be evaluated before any connection is opened")


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


def test_a_dns_failure_is_reported_as_a_typed_transport_error(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def unresolvable(*_args: object, **_kwargs: object) -> None:
        raise socket.gaierror("name or service not known")

    monkeypatch.setattr(socket, "getaddrinfo", unresolvable)

    with pytest.raises(CaptureTransportError, match="dns_resolution_failed") as failure:
        system_resolver("example.test", 443)

    # The raw OSError must stay attached: without it the operator cannot tell a typo
    # in the engagement scope from a broken resolver in the worker container.
    assert isinstance(failure.value.__cause__, socket.gaierror)


@pytest.mark.parametrize(
    ("denied_scope", "target"),
    [
        (
            EngagementScope.create(
                allowed_hostnames=("example.test",),
                allowed_ports=(443,),
                valid_until=datetime(2020, 1, 1, tzinfo=UTC),
            ),
            "https://example.test/",
        ),
        (
            EngagementScope.create(
                allowed_hostnames=("example.test",),
                allowed_ports=(443,),
                valid_from=datetime(2999, 1, 1, tzinfo=UTC),
            ),
            "https://example.test/",
        ),
        (scope(), "https://other.test/"),
        (scope(), "https://example.test:8443/"),
        (
            EngagementScope.create(
                allowed_hostnames=("example.test",),
                allowed_ports=(80,),
                allowed_schemes=("https",),
            ),
            "http://example.test/",
        ),
        (
            EngagementScope.create(
                allowed_hostnames=("example.test",),
                allowed_ports=(443,),
                denied_paths=("/admin",),
            ),
            "https://example.test/admin/users",
        ),
    ],
    ids=[
        "engagement_expired",
        "engagement_not_started",
        "hostname_out_of_scope",
        "port_out_of_scope",
        "scheme_out_of_scope",
        "path_denied",
    ],
)
def test_an_out_of_scope_target_is_refused_before_any_dns_lookup_or_connection(
    denied_scope: EngagementScope, target: str
) -> None:
    transport = PinnedHttpTransport(
        denied_scope,
        resolver=refuse_resolution,
        connection_factory=refuse_connection,
    )

    with pytest.raises(CaptureTransportError, match="transport_scope_denied"):
        transport.send(request_to(target), HttpCaptureLimits())


def test_the_response_byte_limit_holds_when_no_content_length_is_declared() -> None:
    # A chunked or Connection-close response declares no length, so the only defence
    # left is the bounded read; if it goes, an unbounded body lands in the evidence store.
    oversized = FakeConnection(FakeResponse(b"x" * 33))
    transport = PinnedHttpTransport(
        scope(),
        resolver=lambda _host, _port: ("93.184.216.34",),
        connection_factory=lambda *_args: oversized,
    )
    with pytest.raises(CaptureTransportError, match="response_body_too_large"):
        transport.send(request(), HttpCaptureLimits(max_response_bytes=32))
    assert oversized.response.reads == [33]

    exact = FakeConnection(FakeResponse(b"x" * 32))
    at_limit = PinnedHttpTransport(
        scope(),
        resolver=lambda _host, _port: ("93.184.216.34",),
        connection_factory=lambda *_args: exact,
    )
    response = at_limit.send(request(), HttpCaptureLimits(max_response_bytes=32))

    assert response.body == b"x" * 32


@pytest.mark.parametrize(
    "declared_length",
    ["not-a-number", "10, 20", "-1", "", "0x10"],
)
def test_an_unusable_content_length_is_refused_before_the_body_is_read(
    declared_length: str,
) -> None:
    # "10, 20" is what http.client hands back for two conflicting Content-Length headers,
    # the classic request-smuggling signal: refuse rather than pick one and read on.
    connection = FakeConnection(FakeResponse(headers=(("Content-Length", declared_length),)))
    transport = PinnedHttpTransport(
        scope(),
        resolver=lambda _host, _port: ("93.184.216.34",),
        connection_factory=lambda *_args: connection,
    )

    with pytest.raises(CaptureTransportError, match="invalid_content_length"):
        transport.send(request(), HttpCaptureLimits())

    assert connection.response.reads == []
    assert connection.closed


@pytest.mark.parametrize(
    "failure",
    [
        ConnectionResetError("connection reset by peer"),
        ssl.SSLError("record layer failure"),
        http.client.BadStatusLine("garbage"),
    ],
    ids=["socket_reset", "tls_error", "malformed_status_line"],
)
def test_a_network_failure_is_wrapped_and_still_closes_the_connection(
    failure: Exception,
) -> None:
    connection = FailingConnection(failure)
    transport = PinnedHttpTransport(
        scope(),
        resolver=lambda _host, _port: ("93.184.216.34",),
        connection_factory=lambda *_args: connection,
    )

    with pytest.raises(CaptureTransportError, match="network_transport_failed") as wrapped:
        transport.send(request(), HttpCaptureLimits())

    assert wrapped.value.__cause__ is failure
    assert connection.closed


class NineNineNineResponse(FakeResponse):
    """A status code http.client accepts but the evidence model will not model."""

    status = 999


@pytest.mark.parametrize(
    "response",
    [
        FakeResponse(headers=(("X-Cache", ""),)),
        NineNineNineResponse(),
    ],
    ids=["empty_header_value", "out_of_range_status"],
)
def test_response_metadata_the_evidence_model_rejects_surfaces_as_a_typed_refusal(
    response: FakeResponse,
) -> None:
    # Both inputs are server-controlled and occur in the wild: RFC 9110 permits an empty
    # field value, and some sites answer 999. The transport must refuse with its own typed
    # error, or the coordinator records an opaque "transport_failure" and the operator
    # cannot tell a hostile response apart from a bug in the transport itself.
    connection = FakeConnection(response)
    transport = PinnedHttpTransport(
        scope(),
        resolver=lambda _host, _port: ("93.184.216.34",),
        connection_factory=lambda *_args: connection,
    )

    with pytest.raises(CaptureTransportError, match="invalid_response_metadata"):
        transport.send(request(), HttpCaptureLimits())


def test_tls_verifies_the_scoped_hostname_while_the_socket_goes_to_the_pinned_address(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # The whole point of pinning: the TCP connection goes to the address resolved and
    # scope-checked a moment ago, while the certificate is still checked against the
    # hostname in scope. Verifying the IP instead would make every capture fail; keeping
    # the hostname for connect() would leave a rebinding window between check and connect.
    recorder = RecordingSocket()
    attempts = pin_socket(monkeypatch, recorder)
    context = StubSslContext()

    connection = _PinnedHttpsConnection(
        "example.test",
        "93.184.216.34",
        443,
        timeout=5,
        context=cast(ssl.SSLContext, context),
    )
    connection.connect()

    assert attempts == [("93.184.216.34", 443)]
    assert context.server_hostnames == ["example.test"]
    assert connection.sock is context.wrapped
    assert not recorder.closed


def test_a_rejected_certificate_closes_the_pinned_socket_and_fails_closed(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    recorder = RecordingSocket()
    pin_socket(monkeypatch, recorder)
    context = StubSslContext(failure=ssl.SSLCertVerificationError("certificate verify failed"))
    transport = PinnedHttpTransport(
        scope(),
        resolver=lambda _host, _port: ("93.184.216.34",),
        ssl_context=cast(ssl.SSLContext, context),
    )

    with pytest.raises(CaptureTransportError, match="network_transport_failed"):
        transport.send(request(), HttpCaptureLimits())

    # A half-open TCP session to the target after a refused handshake is both a leaked
    # descriptor in the worker and an unexplained connection in the client's logs.
    assert recorder.closed


def test_an_https_target_answering_in_cleartext_is_refused_rather_than_read() -> None:
    listener = socket.socket()
    listener.bind(("127.0.0.1", 0))
    listener.listen(1)
    port = listener.getsockname()[1]

    def answer_in_cleartext() -> None:
        try:
            accepted, _ = listener.accept()
        except OSError:
            return
        with closing(accepted):
            accepted.sendall(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok")

    thread = threading.Thread(target=answer_in_cleartext, daemon=True)
    thread.start()
    try:
        local_scope = EngagementScope.create(
            allowed_cidrs=("127.0.0.1/32",),
            allowed_ports=(port,),
            allowed_schemes=("https",),
        )

        # No silent downgrade: a port that speaks plaintext must never be captured as if
        # the https scope entry had been honoured.
        with pytest.raises(CaptureTransportError, match="network_transport_failed"):
            PinnedHttpTransport(local_scope).send(
                request_to(f"https://127.0.0.1:{port}/"),
                HttpCaptureLimits(timeout_seconds=5, max_response_bytes=64),
            )
    finally:
        listener.close()
        thread.join(timeout=2)


def test_the_default_tls_context_verifies_certificates_and_hostnames() -> None:
    context = PinnedHttpTransport(scope())._ssl_context

    assert context.check_hostname
    assert context.verify_mode is ssl.CERT_REQUIRED
