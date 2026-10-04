"""DNS-pinned transport for authenticated probes.

This is the network implementation behind
:class:`~vuln_proof_claw.agent.authsession.AuthenticatedTransport`. It reuses the DNS
pinning, SSRF guard, and connection primitives from
:mod:`vuln_proof_claw.execution.pinned_http` rather than reimplementing them: security
logic duplicated is security logic that drifts.

It differs from the capture transport in exactly two ways, both required for
authenticated differential testing and both kept as narrow as possible:

* a ``cookie`` and ``content-type`` header may be sent, because a session cannot be
  carried otherwise;
* the single configured login path may receive a ``POST``.

Everything else is unchanged: scope is evaluated before connecting, the connection is
pinned to a validated literal address, redirects are never followed, and the response
is bounded.
"""

from __future__ import annotations

import ipaddress
import ssl
import time
from collections.abc import Callable
from typing import Final

from vuln_proof_claw.agent.authsession import (
    AuthenticatedTransport,
    ProbeLimits,
    RawResponse,
)
from vuln_proof_claw.domain.models import utc_now
from vuln_proof_claw.execution.http_capture import CaptureTransportError
from vuln_proof_claw.execution.pinned_http import (
    AddressResolver,
    HttpConnection,
    _connection_factory,
    system_resolver,
)
from vuln_proof_claw.policy.scope import (
    EngagementScope,
    evaluate_scope,
    normalize_target,
)

_ALLOWED_METHODS: Final = frozenset({"GET", "HEAD", "POST"})
_ALLOWED_OUTBOUND: Final = frozenset({"accept", "user-agent", "content-type", "cookie"})
_MAX_HEADER_BYTES: Final = 16 * 1024
_MILLISECONDS: Final = 1000


class PinnedAuthTransport(AuthenticatedTransport):
    """Send one authenticated request to a scope-approved, DNS-pinned address.

    ``login_path`` is the only path permitted to receive a POST. Anything else is
    refused before a socket is opened, so a planner cannot turn a read sweep into a
    state-changing one.
    """

    identity = "pinned-auth-http/v1"

    def __init__(  # noqa: PLR0913 - explicit injection points for testing
        self,
        scope: EngagementScope,
        *,
        login_path: str | None = None,
        resolver: AddressResolver = system_resolver,
        ssl_context: ssl.SSLContext | None = None,
        connection_factory: Callable[..., HttpConnection] = _connection_factory,
        allow_private: bool = False,
    ) -> None:
        self._scope = scope
        self._login_path = login_path
        self._resolver = resolver
        self._ssl_context = ssl_context or ssl.create_default_context()
        self._connection_factory = connection_factory
        self._allow_private = allow_private

    def send(
        self,
        method: str,
        target: str,
        *,
        headers: tuple[tuple[str, str], ...],
        body: str | None,
        limits: ProbeLimits,
    ) -> RawResponse:
        """Perform the request, enforcing every boundary before connecting."""
        normalized_method = method.upper()
        if normalized_method not in _ALLOWED_METHODS:
            raise CaptureTransportError("method_not_allowed")

        parsed = normalize_target(target)
        if normalized_method == "POST" and parsed.path != self._login_path:
            raise CaptureTransportError("post_permitted_only_on_the_login_path")
        if body is not None and normalized_method != "POST":
            raise CaptureTransportError("body_permitted_only_on_post")

        decision = evaluate_scope(parsed, self._scope, at=utc_now())
        if not decision.allowed:
            raise CaptureTransportError("transport_scope_denied")

        self._require_permitted(headers)
        address = self._validated_addresses(parsed.host, parsed.port)[0]

        connection = self._connection_factory(
            parsed.scheme,
            parsed.host,
            address,
            parsed.port,
            limits.timeout_seconds,
            self._ssl_context,
        )
        started = time.monotonic()
        try:
            payload = body.encode() if body is not None else None
            connection.request(
                normalized_method,
                parsed.path,
                body=payload,
                headers=dict(headers),
            )
            response = connection.getresponse()
            content = response.read(limits.max_response_bytes + 1)
            if len(content) > limits.max_response_bytes:
                raise CaptureTransportError("response_body_too_large")
            received = tuple(
                (name.lower(), value) for name, value in response.getheaders()
            )
            status = response.status
        except CaptureTransportError:
            raise
        except (OSError, ssl.SSLError, ValueError) as error:
            raise CaptureTransportError("transport_request_failed") from error
        finally:
            connection.close()

        elapsed = int((time.monotonic() - started) * _MILLISECONDS)
        return RawResponse(
            status_code=status,
            headers=received,
            body=content,
            elapsed_ms=elapsed,
        )

    @staticmethod
    def _require_permitted(headers: tuple[tuple[str, str], ...]) -> None:
        total = 0
        for name, value in headers:
            if name.lower() not in _ALLOWED_OUTBOUND:
                raise CaptureTransportError("request_header_not_allowed")
            total += len(name) + len(value)
        if total > _MAX_HEADER_BYTES:
            raise CaptureTransportError("request_headers_too_large")

    def _validated_addresses(self, hostname: str, port: int) -> tuple[str, ...]:
        """Resolve and validate, refusing anything the scope does not permit.

        Mirrors the capture transport's guard: a denied network is refused outright, and
        a non-global address is refused unless the scope allows that network explicitly.
        """
        candidates = self._resolver(hostname, port)
        if not candidates:
            raise CaptureTransportError("dns_resolution_empty")
        validated: list[str] = []
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
            if not address.is_global and not explicitly_allowed and not self._allow_private:
                raise CaptureTransportError("resolved_address_not_public")
            validated.append(str(address))
        return tuple(validated)


__all__ = ["PinnedAuthTransport"]
