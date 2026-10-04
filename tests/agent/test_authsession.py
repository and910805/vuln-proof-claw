"""Tests for authenticated differential probing.

The security property under test is containment: a credential must reach the transport
and nothing else. Several tests assert the absence of a secret rather than the presence
of a feature, because that is the failure that matters.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import UTC, datetime

import pytest

from tests.agent.support import TARGET_HOST
from vuln_proof_claw.agent.authsession import (
    AuthenticationError,
    IdentitySessions,
    ProbeError,
    ProbeLimits,
    RawResponse,
    SessionState,
    redact_outbound,
)
from vuln_proof_claw.agent.endpoints import ProbeStrategy
from vuln_proof_claw.config.identities import (
    parse_identity_bundle,
    resolve_credentials,
)
from vuln_proof_claw.policy.scope import EngagementScope

NOW = datetime(2026, 10, 4, 12, 0, tzinfo=UTC)
PASSWORD = "sup3r-s3cret-value"  # noqa: S105 - test credential
SESSION_TOKEN = "abcdef0123456789"  # noqa: S105 - test credential

BUNDLE_YAML = f"""
base_url: https://{TARGET_HOST}
login:
  method: POST
  path: /web/login
  content_type: application/json
  body: '{{"username": "{{username}}", "password": "{{password}}"}}'
  success_statuses: [200]
  session_cookies: ["session"]
identities:
  - name: anonymous
    role: anonymous
  - name: account24
    role: user
    credentials:
      username: account24
      password: {PASSWORD}
  - name: account25
    role: user
    credentials:
      username: account25
      password: {PASSWORD}
"""

SCOPE = EngagementScope.create(
    allowed_hostnames=(TARGET_HOST,),
    allowed_ports=(443,),
    allowed_schemes=("https",),
)


@dataclass(frozen=True, slots=True)
class SentRequest:
    """One request as it left the session layer."""

    method: str
    target: str
    headers: tuple[tuple[str, str], ...]
    body: str | None


@dataclass
class RecordingTransport:
    """Captures every outgoing request so tests can inspect what was actually sent."""

    login_status: int = 200
    login_cookie: str | None = f"session={SESSION_TOKEN}; Path=/; HttpOnly"
    probe_status: int = 200
    probe_body: bytes = b'{"id":42,"owner":"account24"}' * 8
    sent: list[SentRequest] = field(default_factory=list)

    def send(
        self,
        method: str,
        target: str,
        *,
        headers: tuple[tuple[str, str], ...],
        body: str | None,
        limits: ProbeLimits,
    ) -> RawResponse:
        self.sent.append(SentRequest(method, target, headers, body))
        if method == "POST":
            response_headers: tuple[tuple[str, str], ...] = (
                (("set-cookie", self.login_cookie),) if self.login_cookie else ()
            )
            return RawResponse(self.login_status, response_headers, b"{}", elapsed_ms=12)
        return RawResponse(
            self.probe_status,
            (("content-type", "application/json"),),
            self.probe_body,
            elapsed_ms=7,
        )


def build(transport: RecordingTransport) -> IdentitySessions:
    bundle = parse_identity_bundle(BUNDLE_YAML)
    credentials, _ = resolve_credentials(bundle)
    return IdentitySessions(
        transport=transport,  # type: ignore[arg-type]
        bundle=bundle,
        credentials=credentials,
        scope=SCOPE,
    )


def test_a_successful_login_establishes_a_session() -> None:
    transport = RecordingTransport()
    sessions = build(transport)

    state = sessions.authenticate("account24", at=NOW)

    assert state.authenticated
    assert state.cookies == {"session": SESSION_TOKEN}
    assert sessions.authenticated_identities() == ("account24",)


def test_the_credential_reaches_the_transport_and_nowhere_else() -> None:
    """The password may appear in the login body — and in nothing the caller can see."""
    transport = RecordingTransport()
    sessions = build(transport)

    sessions.authenticate("account24", at=NOW)
    sessions.probe("account24", "GET", f"https://{TARGET_HOST}/web/files/42", at=NOW)

    login_body = str(transport.sent[0].body)
    assert PASSWORD in login_body  # the transport is the one place it belongs

    # Everywhere the caller can reach, the secret must be absent.
    assert PASSWORD not in str(transport.sent[1])
    assert PASSWORD not in repr(sessions)
    assert PASSWORD not in repr(sessions.bundle)
    assert PASSWORD not in repr(sessions.credentials)
    assert PASSWORD not in str(sessions.authenticated_identities())


def test_the_parsed_bundle_never_exposes_the_password() -> None:
    """A bundle is held in memory between parsing and resolution; it must be safe there."""
    bundle = parse_identity_bundle(BUNDLE_YAML)

    assert PASSWORD not in repr(bundle)
    assert PASSWORD not in str(bundle.model_dump())
    credential = bundle.named("account24")
    assert credential is not None
    assert credential.credentials is not None
    # The value is still retrievable deliberately, but only by asking for it.
    assert credential.credentials.password.get_secret_value() == PASSWORD


def test_resolved_credentials_do_not_leak_through_repr() -> None:
    bundle = parse_identity_bundle(BUNDLE_YAML)

    credentials, literals = resolve_credentials(bundle)

    assert PASSWORD not in repr(credentials)
    assert "account24" in literals  # the file held a literal, and we say so


def test_a_probe_result_never_carries_the_session_cookie() -> None:
    """ProbeResult is what reaches the oracle and the evidence chain."""
    transport = RecordingTransport()
    sessions = build(transport)
    sessions.authenticate("account24", at=NOW)

    result = sessions.probe("account24", "GET", f"https://{TARGET_HOST}/web/files/42", at=NOW)

    serialised = repr(result)
    assert SESSION_TOKEN not in serialised
    assert PASSWORD not in serialised
    assert result.identity == "account24"
    assert result.body_size == len(transport.probe_body)


def test_the_session_cookie_is_sent_on_probes() -> None:
    transport = RecordingTransport()
    sessions = build(transport)
    sessions.authenticate("account24", at=NOW)

    sessions.probe("account24", "GET", f"https://{TARGET_HOST}/web/files/42", at=NOW)

    headers = dict(transport.sent[1].headers)
    assert headers["cookie"] == f"session={SESSION_TOKEN}"


def test_two_identities_hold_separate_sessions() -> None:
    transport = RecordingTransport()
    sessions = build(transport)

    sessions.authenticate("account24", at=NOW)
    transport.login_cookie = "session=zzzz-other-session"
    sessions.authenticate("account25", at=NOW)

    assert sessions.authenticated_identities() == ("account24", "account25")
    first = sessions.probe("account24", "GET", f"https://{TARGET_HOST}/x", at=NOW)
    second = sessions.probe("account25", "GET", f"https://{TARGET_HOST}/x", at=NOW)
    assert first.identity != second.identity


def test_the_anonymous_identity_needs_no_login() -> None:
    transport = RecordingTransport()
    sessions = build(transport)

    state = sessions.authenticate("anonymous", at=NOW)
    sessions.probe("anonymous", "GET", f"https://{TARGET_HOST}/x", at=NOW)

    assert not state.authenticated
    assert all(sent.method != "POST" for sent in transport.sent)
    assert "cookie" not in dict(transport.sent[0].headers)


def test_a_rejected_login_raises_rather_than_returning_a_blank_session() -> None:
    transport = RecordingTransport(login_status=401)
    sessions = build(transport)

    with pytest.raises(AuthenticationError, match="returned 401"):
        sessions.authenticate("account24", at=NOW)


def test_a_login_that_returns_no_cookie_is_a_failure() -> None:
    """A 200 with no session is a silent failure that would poison every later probe."""
    transport = RecordingTransport(login_cookie=None)
    sessions = build(transport)

    with pytest.raises(AuthenticationError, match="no session cookie"):
        sessions.authenticate("account24", at=NOW)


def test_only_the_configured_session_cookie_is_kept() -> None:
    transport = RecordingTransport(
        login_cookie="session=keep-me; Path=/, tracking=discard-me; Path=/"
    )
    sessions = build(transport)

    state = sessions.authenticate("account24", at=NOW)

    assert state.cookies == {"session": "keep-me"}


def test_a_probe_outside_scope_is_refused() -> None:
    transport = RecordingTransport()
    sessions = build(transport)
    sessions.authenticate("account24", at=NOW)

    with pytest.raises(ProbeError, match="outside the authorized scope"):
        sessions.probe("account24", "GET", "https://attacker.test/x", at=NOW)

    assert len(transport.sent) == 1  # only the login


def test_probing_without_authenticating_first_is_refused() -> None:
    sessions = build(RecordingTransport())

    with pytest.raises(ProbeError, match="no session"):
        sessions.probe("account24", "GET", f"https://{TARGET_HOST}/x", at=NOW)


@pytest.mark.parametrize("method", ["POST", "PUT", "DELETE", "PATCH"])
def test_a_direct_probe_may_only_read(method: str) -> None:
    """Differential probing must never change state on the target."""
    transport = RecordingTransport()
    sessions = build(transport)
    sessions.authenticate("account24", at=NOW)

    with pytest.raises(ProbeError, match="GET or HEAD only"):
        sessions.probe("account24", method, f"https://{TARGET_HOST}/x", at=NOW)


@pytest.mark.parametrize("method", ["GET", "PUT", "DELETE", "PATCH"])
def test_an_empty_body_probe_is_sent_as_post_only(method: str) -> None:
    """Pairing a strategy with any method would make the strategy meaningless."""
    sessions = build(RecordingTransport())
    sessions.authenticate("account24", at=NOW)

    with pytest.raises(ProbeError, match="POST only"):
        sessions.probe(
            "account24",
            method,
            f"https://{TARGET_HOST}/x",
            strategy=ProbeStrategy.EMPTY_BODY,
            at=NOW,
        )


def test_a_destructive_endpoint_is_never_probed() -> None:
    transport = RecordingTransport()
    sessions = build(transport)
    sessions.authenticate("account24", at=NOW)

    with pytest.raises(ProbeError, match="destructive"):
        sessions.probe(
            "account24",
            "POST",
            f"https://{TARGET_HOST}/api/setDeviceSecureWipe",
            strategy=ProbeStrategy.REFUSE,
            at=NOW,
        )

    assert all("setDeviceSecureWipe" not in request.target for request in transport.sent)


def test_an_empty_body_probe_carries_nothing_to_act_on() -> None:
    """The containment is the body: an incomplete request cannot complete an action."""
    transport = RecordingTransport()
    sessions = build(transport)
    sessions.authenticate("account24", at=NOW)
    before = len(transport.sent)

    sessions.probe(
        "account24",
        "POST",
        f"https://{TARGET_HOST}/api/getCompanyDisplay",
        strategy=ProbeStrategy.EMPTY_BODY,
        at=NOW,
    )

    sent = transport.sent[before]
    assert sent.body == "{}"
    assert sent.method == "POST"
    assert ("content-type", "application/json") in sent.headers


def test_an_unknown_identity_is_refused() -> None:
    sessions = build(RecordingTransport())

    with pytest.raises(AuthenticationError, match="unknown identity"):
        sessions.authenticate("nobody", at=NOW)


def test_outbound_headers_are_redacted_for_recording() -> None:
    redacted = dict(
        redact_outbound(
            (
                ("cookie", f"session={SESSION_TOKEN}"),
                ("accept", "*/*"),
                ("authorization", "Bearer x"),
            )
        )
    )

    assert redacted["cookie"] == "[REDACTED]"
    assert redacted["authorization"] == "[REDACTED]"
    assert redacted["accept"] == "*/*"


def test_session_state_does_not_leak_through_repr() -> None:
    state = SessionState(cookies={"session": SESSION_TOKEN})

    assert SESSION_TOKEN not in repr(state)
