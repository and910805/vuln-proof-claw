"""Authenticated sessions for differential testing.

This is the only place in the system that sends a credential, and the only place that
holds a session cookie. The design keeps that blast radius small:

* A probe request carries an **identity name**, never a credential and never a cookie.
  Requests are therefore safe to serialise into the evidence chain.
* Cookies live in this module's memory for the lifetime of a session and are injected
  at send time.
* Everything recorded about a request has its ``cookie`` and ``authorization`` headers
  redacted before it leaves this module.

It deliberately does *not* reuse the worker capture path. That path allows only GET and
HEAD with a two-header allowlist, and those limits protect the disposable container
boundary. Rather than widen them, this module provides a separate, equally narrow
channel: one configured login endpoint may receive a POST, a classified endpoint may
receive a POST carrying nothing, and everything else is a read.

The empty-body POST exists because most of the APIs worth testing expose their reads
over POST. Sending one changes nothing — the request is deliberately incomplete, so it
fails in the target's own validation layer — but the *shape* of that failure still
answers the question that matters: does authentication run before the business logic?
It is permitted only for an endpoint the classifier has already judged, never on a
caller's say-so.
"""

from __future__ import annotations

import logging
import re
from dataclasses import dataclass, field
from datetime import UTC, datetime
from http.cookies import SimpleCookie
from typing import Final

from vuln_proof_claw.agent.differential import ProbeResult, body_digest
from vuln_proof_claw.agent.endpoints import ProbeStrategy
from vuln_proof_claw.config.identities import (
    IdentityBundle,
    LoginFlow,
    ResolvedCredential,
)
from vuln_proof_claw.config.redaction import REDACTED, is_sensitive_key
from vuln_proof_claw.policy.scope import EngagementScope, evaluate_scope, normalize_target

_LOGGER = logging.getLogger(__name__)

#: Headers this module may add to an outgoing request. Narrow on purpose: everything
#: here is either required to speak to the target or supplied by the login flow.
_PERMITTED_OUTBOUND = frozenset({"accept", "user-agent", "content-type", "cookie"})

_DEFAULT_USER_AGENT = "vuln-proof-claw/authenticated-probe"

#: The entire body of an empty-body probe. No identifier, no value, nothing to act on.
#: Public because the transport checks for it byte for byte: that check is what makes
#: "this POST changes nothing" a property of the request rather than a claim about it.
EMPTY_PROBE_BODY: Final = "{}"
_EMPTY_BODY_CONTENT_TYPE = "application/json"

_MAX_RESPONSE_BYTES = 2 * 1024 * 1024
_REDIRECT_MIN = 300
_REDIRECT_MAX = 399


class AuthenticationError(Exception):
    """Raised when an identity cannot be authenticated."""


class ProbeError(Exception):
    """Raised when a probe cannot be performed safely."""


@dataclass(frozen=True, slots=True)
class ProbeLimits:
    """Bounds applied to every authenticated request."""

    timeout_seconds: int = 15
    max_response_bytes: int = _MAX_RESPONSE_BYTES


@dataclass(frozen=True, slots=True)
class RawResponse:
    """What a transport returned, before any interpretation."""

    status_code: int
    headers: tuple[tuple[str, str], ...]
    body: bytes
    elapsed_ms: int = 0


class AuthenticatedTransport:
    """Network boundary for authenticated requests.

    Implementations must enforce scope, pin DNS, refuse to follow redirects, and bound
    the response. The in-process implementation reuses
    :class:`~vuln_proof_claw.execution.pinned_http.PinnedHttpTransport` primitives.
    """

    def send(
        self,
        method: str,
        target: str,
        *,
        headers: tuple[tuple[str, str], ...],
        body: str | None,
        limits: ProbeLimits,
    ) -> RawResponse:
        """Send one request and return a bounded response."""
        raise NotImplementedError


def extract_hidden_field(html: str, name: str) -> str | None:
    """Return the value of a hidden input, or None when the page has no such field.

    Deliberately narrow: it reads one named field out of the markup and does nothing
    else with the page. Returning None rather than an empty string keeps "the field was
    absent" distinguishable from "the field was empty", which are different failures.
    """
    pattern = re.compile(
        r"<input\b[^>]*\bname\s*=\s*[\"']" + re.escape(name) + r"[\"'][^>]*>",
        re.IGNORECASE,
    )
    match = pattern.search(html)
    if match is None:
        return None
    value = re.search(
        r"\bvalue\s*=\s*[\"']([^\"']*)[\"']", match.group(0), re.IGNORECASE
    )
    return value.group(1) if value else ""


def redact_outbound(headers: tuple[tuple[str, str], ...]) -> tuple[tuple[str, str], ...]:
    """Mask credential-bearing headers for logging and evidence."""
    return tuple(
        (name, REDACTED if is_sensitive_key(name) else value) for name, value in headers
    )


@dataclass
class SessionState:
    """Cookies held for one identity. Never serialised."""

    cookies: dict[str, str] = field(default_factory=dict, repr=False)
    established_at: datetime | None = None

    @property
    def authenticated(self) -> bool:
        return bool(self.cookies)

    def header(self) -> tuple[tuple[str, str], ...]:
        if not self.cookies:
            return ()
        value = "; ".join(f"{name}={token}" for name, token in sorted(self.cookies.items()))
        return (("cookie", value),)

    def absorb(self, headers: tuple[tuple[str, str], ...], *, keep: tuple[str, ...]) -> None:
        """Record Set-Cookie values, keeping only the configured session cookies."""
        for name, value in headers:
            if name.lower() != "set-cookie":
                continue
            jar = SimpleCookie()
            jar.load(value)
            for key, morsel in jar.items():
                if not keep or key in keep:
                    self.cookies[key] = morsel.value


@dataclass
class IdentitySessions:
    """Authenticate identities and perform reads as them.

    ``scope`` and ``base_url`` come from the stored engagement, not from the identity
    file, so a misconfigured identity cannot widen the authorized boundary.
    """

    transport: AuthenticatedTransport = field(repr=False)
    bundle: IdentityBundle = field(repr=False)
    credentials: dict[str, ResolvedCredential] = field(repr=False)
    scope: EngagementScope = field(repr=False)
    timeout_seconds: int = 15
    user_agent: str = _DEFAULT_USER_AGENT
    _sessions: dict[str, SessionState] = field(default_factory=dict, init=False, repr=False)

    def authenticate(self, identity: str, *, at: datetime | None = None) -> SessionState:
        """Exchange this identity's credentials for a session.

        The rendered body exists only for the duration of the call. Nothing derived from
        it is returned, logged, or stored.
        """
        definition = self.bundle.named(identity)
        if definition is None:
            raise AuthenticationError(f"unknown identity: {identity}")
        if definition.credentials is None:
            state = SessionState()
            self._sessions[identity] = state
            return state

        login = self.bundle.login
        if login is None:  # pragma: no cover - guarded by bundle validation
            raise AuthenticationError("bundle has credentials but no login flow")
        credential = self.credentials.get(identity)
        if credential is None:
            raise AuthenticationError(f"no resolved credential for identity: {identity}")

        target = self._absolute(login.path)
        self._require_in_scope(target, at=at)

        # A form protected by an anti-forgery token rejects every login that does not
        # carry one, so the token and the cookie set alongside it are fetched first and
        # travel together into the POST — the same two steps a browser performs.
        state = SessionState(established_at=at or datetime.now(UTC))
        csrf = self._collect_token(login, state, at=at) if login.csrf_field else ""

        response = self.transport.send(
            login.method,
            target,
            headers=(
                ("content-type", login.content_type),
                ("user-agent", self.user_agent),
                ("accept", "*/*"),
                *state.header(),
            ),
            body=login.render(
                credential.username.get_secret_value(),
                credential.password.get_secret_value(),
                csrf,
            ),
            limits=ProbeLimits(timeout_seconds=self.timeout_seconds),
        )
        self._accept_login(identity, login, response, state=state)
        self._sessions[identity] = state
        return state

    def _collect_token(
        self, login: LoginFlow, state: SessionState, *, at: datetime | None
    ) -> str:
        """Read the anti-forgery token from the login page, keeping its cookies."""
        target = self._absolute(login.token_path)
        self._require_in_scope(target, at=at)
        response = self.transport.send(
            "GET",
            target,
            headers=(("accept", "*/*"), ("user-agent", self.user_agent)),
            body=None,
            limits=ProbeLimits(timeout_seconds=self.timeout_seconds),
        )
        # Every cookie is kept here, not only the configured session one: the cookie a
        # server pairs with its token is often a different, short-lived one, and
        # discarding it invalidates the token we just read.
        state.absorb(response.headers, keep=())
        field = login.csrf_field or ""
        token = extract_hidden_field(
            response.body.decode("utf-8", errors="replace"), field
        )
        if token is None:
            raise AuthenticationError(
                f"login page did not contain a hidden field named {field!r}"
            )
        return token

    def probe(
        self,
        identity: str,
        method: str,
        target: str,
        *,
        strategy: ProbeStrategy = ProbeStrategy.DIRECT,
        at: datetime | None = None,
    ) -> ProbeResult:
        """Perform one probe as an identity and record only comparable facts.

        The body is reduced to a digest and a length here, before anything else sees it,
        so no downstream component can base a judgement on content it interpreted.
        """
        normalized_method = method.upper()
        extra_headers, body = self._shape(normalized_method, strategy)
        self._require_in_scope(target, at=at)

        state = self._sessions.get(identity)
        if state is None:
            raise ProbeError(f"identity {identity} has no session; authenticate first")

        headers = (
            ("accept", "*/*"),
            ("user-agent", self.user_agent),
            *extra_headers,
            *state.header(),
        )
        self._require_permitted(headers)
        started = at or datetime.now(UTC)
        response = self.transport.send(
            normalized_method,
            target,
            headers=headers,
            body=body,
            limits=ProbeLimits(timeout_seconds=self.timeout_seconds),
        )
        header_map = {name.lower(): value for name, value in response.headers}
        return ProbeResult(
            identity=identity,
            method=normalized_method,
            target=str(normalize_target(target)),
            status_code=response.status_code,
            body_digest=body_digest(response.body),
            body_size=len(response.body),
            content_type=header_map.get("content-type", ""),
            location=header_map.get("location", ""),
            elapsed_ms=response.elapsed_ms,
            observed_at=started,
        )

    @staticmethod
    def _shape(
        method: str, strategy: ProbeStrategy
    ) -> tuple[tuple[tuple[str, str], ...], str | None]:
        """Return the headers and body one strategy permits, or refuse to send.

        Every refusal here is a method the strategy does not sanction. The pairing is
        fixed rather than configurable: a strategy that could be sent with any method
        would be no constraint at all.
        """
        if strategy is ProbeStrategy.REFUSE:
            raise ProbeError("this endpoint is classified as destructive and is never probed")
        if strategy is ProbeStrategy.DIRECT:
            if method not in {"GET", "HEAD"}:
                raise ProbeError("a direct probe is a read; GET or HEAD only")
            return ((), None)
        if method != "POST":
            raise ProbeError("an empty-body probe is sent as POST only")
        return ((("content-type", _EMPTY_BODY_CONTENT_TYPE),), EMPTY_PROBE_BODY)

    def cookie_header(self, identity: str) -> tuple[tuple[str, str], ...]:
        """Return the cookie header for an authenticated identity, or nothing.

        Lets reconnaissance look at a target as a logged-in user. The cookie still
        never leaves this module in any other form: the caller receives a header to
        pass to the transport, not the session, and has no way to read the value back
        out of anything it records.
        """
        state = self._sessions.get(identity)
        return state.header() if state is not None else ()

    def authenticated_identities(self) -> tuple[str, ...]:
        """Return the identities that currently hold a session."""
        return tuple(sorted(name for name, state in self._sessions.items() if state.authenticated))

    def _accept_login(
        self,
        identity: str,
        login: LoginFlow,
        response: RawResponse,
        *,
        state: SessionState,
    ) -> None:
        if response.status_code not in login.success_statuses:
            raise AuthenticationError(
                f"login for {identity} returned {response.status_code}"
            )
        if login.failure_marker and login.failure_marker.encode() in response.body:
            raise AuthenticationError(f"login for {identity} matched the failure marker")

        state.absorb(response.headers, keep=login.session_cookies)
        if not state.authenticated:
            raise AuthenticationError(
                f"login for {identity} returned no session cookie"
                + (f" matching {list(login.session_cookies)}" if login.session_cookies else "")
            )
        _LOGGER.info("identity %s authenticated (%d cookie(s))", identity, len(state.cookies))

    def _absolute(self, path: str) -> str:
        return f"{self.bundle.base_url.rstrip('/')}{path}"

    def _require_in_scope(self, target: str, *, at: datetime | None) -> None:
        decision = evaluate_scope(target, self.scope, at=at or datetime.now(UTC))
        if not decision.allowed:
            raise ProbeError(f"target is outside the authorized scope: {decision.reason}")

    @staticmethod
    def _require_permitted(headers: tuple[tuple[str, str], ...]) -> None:
        for name, _ in headers:
            if name.lower() not in _PERMITTED_OUTBOUND:
                raise ProbeError(f"header not permitted on an authenticated probe: {name}")


def is_redirect(status: int) -> bool:
    """Return whether a status is a redirect, which probes never follow."""
    return _REDIRECT_MIN <= status <= _REDIRECT_MAX


__all__ = [
    "EMPTY_PROBE_BODY",
    "AuthenticatedTransport",
    "AuthenticationError",
    "IdentitySessions",
    "ProbeError",
    "ProbeLimits",
    "RawResponse",
    "SessionState",
    "is_redirect",
    "redact_outbound",
]
