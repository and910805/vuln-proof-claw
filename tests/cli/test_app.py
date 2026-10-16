"""Tests for the decisions the command-line application makes on an operator's behalf."""

from __future__ import annotations

import tempfile
from pathlib import Path

import pytest

from vuln_proof_claw.cli.app import _build_prober, _probing_roles, _sweep_rate
from vuln_proof_claw.config.identities import (
    IdentityDefinitionError,
    inspect_credentials,
    parse_identity_bundle,
)
from vuln_proof_claw.domain.autonomous import MissionBudget
from vuln_proof_claw.execution.pinned_auth_http import PinnedAuthTransport
from vuln_proof_claw.policy.scope import EngagementScope

ANONYMOUS_ONLY = """
base_url: https://target.example.com
identities:
  - name: anonymous
    role: anonymous
"""

TWO_USERS = """
base_url: https://target.example.com
login:
  method: POST
  path: /login
  content_type: application/json
  body: '{"u": "{username}", "p": "{password}"}'
  success_statuses: [200]
  session_cookies: ["session"]
identities:
  - name: anonymous
    role: anonymous
  - name: account24
    role: user
    credentials: {username: account24, password: env:TEST_PASSWORD}
  - name: account25
    role: user
    credentials: {username: account25, password: env:TEST_PASSWORD}
  - name: admin
    role: privileged
    credentials: {username: admin, password: env:TEST_PASSWORD}
"""

NO_USABLE_ROLE = """
base_url: https://target.example.com
login:
  method: POST
  path: /login
  content_type: application/json
  body: '{"u": "{username}", "p": "{password}"}'
  success_statuses: [200]
  session_cookies: ["session"]
identities:
  - name: admin
    role: privileged
    credentials: {username: admin, password: env:TEST_PASSWORD}
"""


PENDING_BUNDLE = """
base_url: https://target.example.com
login:
  method: POST
  path: /login
  content_type: application/json
  body: '{"u": "{username}", "p": "{password}"}'
  success_statuses: [200]
  session_cookies: ["session"]
identities:
  - name: anonymous
    role: anonymous
  - name: account24
    role: user
    credentials: {username: "${SUPPLIED_USER}", password: "${SUPPLIED_PASS}"}
  - name: admin
    role: privileged
    credentials: {username: "${UNSET_ADMIN_USER}", password: "${UNSET_ADMIN_PASS}"}
"""


def test_a_missing_credential_is_reported_not_raised(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """An agent meant to run for days must not fall over on an unfilled password."""
    monkeypatch.setenv("SUPPLIED_USER", "account24")
    monkeypatch.setenv("SUPPLIED_PASS", "not-a-real-password")
    monkeypatch.delenv("UNSET_ADMIN_USER", raising=False)
    monkeypatch.delenv("UNSET_ADMIN_PASS", raising=False)

    resolution = inspect_credentials(parse_identity_bundle(PENDING_BUNDLE))

    assert not resolution.complete
    assert sorted(resolution.resolved) == ["account24"]
    assert [slot.identity for slot in resolution.pending] == ["admin"]
    assert resolution.pending[0].pending_variables == (
        "UNSET_ADMIN_USER",
        "UNSET_ADMIN_PASS",
    )


def test_a_pending_slot_never_carries_a_value(monkeypatch: pytest.MonkeyPatch) -> None:
    """The report is meant to be pasted into a ticket, so it holds names only."""
    monkeypatch.setenv("SUPPLIED_USER", "account24")
    monkeypatch.setenv("SUPPLIED_PASS", "sup3r-s3cret-value")

    resolution = inspect_credentials(parse_identity_bundle(PENDING_BUNDLE))
    rendered = repr(resolution.slots)

    assert "sup3r-s3cret-value" not in rendered
    assert "account24" in rendered  # the identity name is fine to show


def test_probing_degrades_to_the_identities_that_are_available(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A declared admin nobody has filled in must not take the whole sweep down."""
    monkeypatch.setenv("SUPPLIED_USER", "account24")
    monkeypatch.setenv("SUPPLIED_PASS", "not-a-real-password")
    monkeypatch.delenv("UNSET_ADMIN_USER", raising=False)
    monkeypatch.delenv("UNSET_ADMIN_PASS", raising=False)
    bundle = parse_identity_bundle(PENDING_BUNDLE)
    available = {"anonymous", "account24"}

    owner, _other, privileged = _probing_roles(bundle, available=available)

    assert owner == "account24"
    assert privileged is None  # the comparison it cannot make is simply not attempted


def test_everything_supplied_reports_complete(monkeypatch: pytest.MonkeyPatch) -> None:
    for name in ("SUPPLIED_USER", "UNSET_ADMIN_USER"):
        monkeypatch.setenv(name, "a-user")
    for name in ("SUPPLIED_PASS", "UNSET_ADMIN_PASS"):
        monkeypatch.setenv(name, "not-a-real-password")

    resolution = inspect_credentials(parse_identity_bundle(PENDING_BUNDLE))

    assert resolution.complete
    assert resolution.literals == ()


def test_the_sweep_rate_defaults_to_the_engagement_limit() -> None:
    assert _sweep_rate(MissionBudget(requests_per_minute_per_domain=3), None) == 3


def test_the_sweep_rate_cannot_be_raised_above_the_engagement_limit() -> None:
    """A flag may slow a sweep down; it must not outrun the authorization package."""
    assert _sweep_rate(MissionBudget(requests_per_minute_per_domain=3), 30) == 3


def test_the_sweep_rate_may_be_lowered() -> None:
    assert _sweep_rate(MissionBudget(requests_per_minute_per_domain=30), 5) == 5


def test_the_comparison_identities_come_from_the_declared_roles() -> None:
    owner, other, privileged = _probing_roles(parse_identity_bundle(TWO_USERS))

    assert (owner, other, privileged) == ("account24", "account25", "admin")


def test_a_bundle_without_credentials_probes_anonymously() -> None:
    """Needing no account on the target is the whole point of this configuration."""
    owner, other, privileged = _probing_roles(parse_identity_bundle(ANONYMOUS_ONLY))

    assert owner == "anonymous"
    assert other is None
    assert privileged is None


def test_a_bundle_with_no_usable_baseline_is_refused() -> None:
    with pytest.raises(IdentityDefinitionError, match="'user' or 'anonymous'"):
        _probing_roles(parse_identity_bundle(NO_USABLE_ROLE))


def tmp_bundle(document: str) -> Path:
    """Write a bundle to a temporary file, because _build_prober loads from disk."""
    with tempfile.NamedTemporaryFile(
        "w", suffix=".yaml", delete=False, encoding="utf-8"
    ) as handle:
        handle.write(document)
        return Path(handle.name)


BROWSER_BUNDLE = """
base_url: https://10.26.0.40
login:
  method: POST
  path: /api/web/login
  content_type: application/json
  body: '{"account": "{username}", "password": "{password}"}'
  success_statuses: [200]
  browser:
    login_url: https://10.26.0.40/#/login
    open_selector: button.start
    username_selector: "#textbox-account"
    password_selector: "#textbox-password"
    submit_selector: button.submit
    continue_selector: button.proceed
identities:
  - name: anonymous
    role: anonymous
  - name: account_a
    role: user
    credentials: {username: "${SUPPLIED_USER}", password: "${SUPPLIED_PASS}"}
"""


def test_the_bundle_describes_both_ways_of_signing_in() -> None:
    """A request to send and controls to operate answer different questions, and
    neither is derivable from the other."""
    bundle = parse_identity_bundle(BROWSER_BUNDLE)

    assert bundle.login is not None
    assert bundle.login.path == "/api/web/login"
    assert bundle.login.browser is not None
    assert bundle.login.browser.continue_selector == "button.proceed"


def test_a_bundle_without_a_browser_block_still_parses() -> None:
    """Most targets need only the HTTP login; the page one is an addition."""
    without = BROWSER_BUNDLE[: BROWSER_BUNDLE.index("  browser:")] + (
        BROWSER_BUNDLE[BROWSER_BUNDLE.index("identities:") :]
    )
    bundle = parse_identity_bundle(without)

    assert bundle.login is not None
    assert bundle.login.browser is None


def test_the_probing_transport_is_told_where_the_login_lives(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A POST carrying a body is permitted only at the nominated path, so leaving it
    unset had our own guard reject every configured login."""
    monkeypatch.setenv("SUPPLIED_USER", "account_a")
    monkeypatch.setenv("SUPPLIED_PASS", "not-a-real-password")
    written = tmp_bundle(BROWSER_BUNDLE)
    scope = EngagementScope.create(
        allowed_cidrs=("10.26.0.0/24",), allowed_ports=(443,), allowed_schemes=("https",)
    )

    probing = _build_prober(written, scope=scope, rate=3)

    transport = probing.sessions.transport
    assert isinstance(transport, PinnedAuthTransport)
    # Asserted on the behaviour rather than the attribute: a POST carrying a body is
    # permitted at the login path and nowhere else, which is the property that broke.
    assert transport._post_permitted("/api/web/login", '{"a": 1}')
    assert not transport._post_permitted("/api/web/other", '{"a": 1}')
