"""DNS-pinned, proxy-free HTTP transport for explicitly scoped passive capture."""

from __future__ import annotations

import http.client
import ipaddress
import socket
import ssl
import time
from collections.abc import Callable
from contextlib import closing
from datetime import UTC, datetime
from typing import Any, Protocol

from vuln_proof_claw.domain.errors import DomainValidationError
from vuln_proof_claw.execution.http_capture import (
    CaptureTransportError,
    HttpCaptureLimits,
    HttpCaptureRequest,
    HttpCaptureResponse,
)
from vuln_proof_claw.policy.scope import EngagementScope, evaluate_scope, normalize_target


class AddressResolver(Protocol):
    """Resolve all candidate addresses before a connection is opened."""

    def __call__(self, hostname: str, port: int) -> tuple[str, ...]: ...


class HttpConnection(Protocol):
    def request(self, method: str, url: str, *, headers: dict[str, str]) -> None: ...

    def getresponse(self) -> Any: ...

    def close(self) -> None: ...


def system_resolver(hostname: str, port: int) -> tuple[str, ...]:
    """Resolve unique IPv4/IPv6 addresses without consulting proxy settings."""
    try:
        results = socket.getaddrinfo(hostname, port, type=socket.SOCK_STREAM)
    except OSError as error:
        raise CaptureTransportError("dns_resolution_failed") from error
    return tuple(sorted({str(item[4][0]) for item in results}))


class _PinnedHttpConnection(http.client.HTTPConnection):
    def __init__(self, hostname: str, address: str, port: int, *, timeout: int) -> None:
        super().__init__(hostname, port=port, timeout=timeout)
        self._address = address

    def connect(self) -> None:
        self.sock = socket.create_connection(
            (self._address, self.port),
            self.timeout,
        )


class _PinnedHttpsConnection(http.client.HTTPSConnection):
    def __init__(
        self,
        hostname: str,
        address: str,
        port: int,
        *,
        timeout: int,
        context: ssl.SSLContext,
    ) -> None:
        super().__init__(hostname, port=port, timeout=timeout, context=context)
        self._address = address
        self._ssl_context = context

    def connect(self) -> None:
        raw_socket = socket.create_connection(
            (self._address, self.port),
            self.timeout,
        )
        try:
            self.sock = self._ssl_context.wrap_socket(raw_socket, server_hostname=self.host)
        except Exception:
            raw_socket.close()
            raise


def _connection_factory(  # noqa: PLR0913, PLR0917 - explicit socket binding fields
    scheme: str,
    hostname: str,
    address: str,
    port: int,
    timeout: int,
    context: ssl.SSLContext,
) -> HttpConnection:
    if scheme == "https":
        return _PinnedHttpsConnection(
            hostname,
            address,
            port,
            timeout=timeout,
            context=context,
        )
    return _PinnedHttpConnection(hostname, address, port, timeout=timeout)


class PinnedHttpTransport:
    """Perform one bounded request against a pre-resolved, scope-checked address."""

    identity = "pinned-http/v1"

    def __init__(
        self,
        scope: EngagementScope,
        *,
        resolver: AddressResolver = system_resolver,
        ssl_context: ssl.SSLContext | None = None,
        connection_factory: Callable[..., HttpConnection] = _connection_factory,
    ) -> None:
        self._scope = scope
        self._resolver = resolver
        self._ssl_context = ssl_context or ssl.create_default_context()
        self._connection_factory = connection_factory

    def send(
        self,
        request: HttpCaptureRequest,
        limits: HttpCaptureLimits,
    ) -> HttpCaptureResponse:
        target = normalize_target(request.target)
        decision = evaluate_scope(target, self._scope, at=_utc_now())
        if not decision.allowed:
            raise CaptureTransportError("transport_scope_denied")
        addresses = self._validated_addresses(target.host, target.port)
        address = addresses[0]
        connection = self._connection_factory(
            target.scheme,
            target.host,
            address,
            target.port,
            limits.timeout_seconds,
            self._ssl_context,
        )
        started = time.monotonic()
        try:
            with closing(connection):
                connection.request(
                    request.method,
                    target.path,
                    headers=dict(request.headers),
                )
                response = connection.getresponse()
                declared_length = response.getheader("Content-Length")
                if declared_length is not None and _declared_too_large(
                    declared_length, limits.max_response_bytes
                ):
                    raise CaptureTransportError("response_body_too_large")
                body = response.read(limits.max_response_bytes + 1)
                if len(body) > limits.max_response_bytes:
                    raise CaptureTransportError("response_body_too_large")
                headers = tuple((name, value) for name, value in response.getheaders())
        except CaptureTransportError:
            raise
        except (OSError, ssl.SSLError, http.client.HTTPException) as error:
            raise CaptureTransportError("network_transport_failed") from error
        try:
            return HttpCaptureResponse(
                status_code=response.status,
                final_target=request.target,
                headers=headers,
                body=body,
                duration_ms=max(0, round((time.monotonic() - started) * 1000)),
            )
        except DomainValidationError as error:
            raise CaptureTransportError("invalid_response_metadata") from error

    def _validated_addresses(self, hostname: str, port: int) -> tuple[str, ...]:
        candidates = self._resolver(hostname, port)
        if not candidates:
            raise CaptureTransportError("dns_resolution_empty")
        validated: list[ipaddress.IPv4Address | ipaddress.IPv6Address] = []
        for candidate in candidates:
            try:
                address = ipaddress.ip_address(candidate)
            except ValueError as error:
                raise CaptureTransportError("dns_resolution_invalid") from error
            if any(address in network for network in self._scope.denied_networks):
                raise CaptureTransportError("resolved_address_denied")
            explicitly_allowed = any(
                address in network for network in self._scope.allowed_networks
            )
            if not address.is_global and not explicitly_allowed:
                raise CaptureTransportError("resolved_address_not_public")
            validated.append(address)
        ordered = sorted(validated, key=lambda item: (item.version, item.packed))
        return tuple(str(item) for item in ordered)


def _declared_too_large(value: str, limit: int) -> bool:
    try:
        size = int(value)
    except ValueError as error:
        raise CaptureTransportError("invalid_content_length") from error
    if size < 0:
        raise CaptureTransportError("invalid_content_length")
    return size > limit


def _utc_now() -> datetime:
    return datetime.now(UTC)
