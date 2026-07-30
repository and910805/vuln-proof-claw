"""Tests for target normalization and default-deny scope policy."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest

from vuln_proof_claw.domain.errors import DomainValidationError
from vuln_proof_claw.policy.scope import (
    EngagementScope,
    evaluate_scope,
    normalize_hostname,
    normalize_network,
    normalize_path,
    normalize_target,
)

NOW = datetime(2026, 7, 30, 12, 0, tzinfo=UTC)


def test_normalizes_dns_ip_cidr_and_url_components() -> None:
    assert normalize_hostname("EXAMPLE.COM.") == "example.com"
    assert normalize_hostname("bücher.example") == "xn--bcher-kva.example"
    assert normalize_hostname("2001:0db8::1") == "2001:db8::1"
    assert str(normalize_network("192.0.2.9/24")) == "192.0.2.0/24"

    target = normalize_target("HTTPS://Example.COM:443/api/../health?token=ignored#fragment")
    assert str(target) == "https://example.com:443/health"


def test_normalizes_nested_encoded_path_before_scope_comparison() -> None:
    assert normalize_path("/public/%252e%252e/admin") == "/admin"


@pytest.mark.parametrize(
    "target",
    [
        "https://user:password@example.com/",
        "ftp://example.com/",
        "https://example.com:70000/",
        "https://example.com/%ZZ",
        "https://example.com/%FF",
        "https://example.com/path\\admin",
    ],
)
def test_rejects_ambiguous_or_unsupported_targets(target: str) -> None:
    with pytest.raises(DomainValidationError):
        normalize_target(target)


def test_scope_denies_take_precedence_over_allows() -> None:
    scope = EngagementScope.create(
        allowed_hostnames=("example.com",),
        allowed_ports=(443,),
        allowed_paths=("/api",),
        denied_paths=("/api/admin",),
    )

    allowed = evaluate_scope("https://example.com/api/users", scope, at=NOW)
    denied = evaluate_scope("https://example.com/api/admin/users", scope, at=NOW)
    boundary = evaluate_scope("https://example.com/apix", scope, at=NOW)

    assert allowed.allowed
    assert allowed.requires_dns_recheck
    assert denied.reason == "path_denied"
    assert boundary.reason == "path_not_allowed"


def test_scope_allows_ip_only_when_it_is_in_an_allowed_network() -> None:
    scope = EngagementScope.create(
        allowed_cidrs=("192.0.2.0/24",),
        denied_cidrs=("192.0.2.128/25",),
        allowed_ports=(8443,),
    )

    allowed = evaluate_scope("https://192.0.2.10:8443/", scope, at=NOW)
    denied = evaluate_scope("https://192.0.2.200:8443/", scope, at=NOW)
    outside = evaluate_scope("https://198.51.100.10:8443/", scope, at=NOW)

    assert allowed.allowed
    assert not allowed.requires_dns_recheck
    assert denied.reason == "network_denied"
    assert outside.reason == "host_not_allowed"


def test_scope_enforces_engagement_time_window() -> None:
    scope = EngagementScope.create(
        allowed_hostnames=("example.com",),
        valid_from=NOW,
        valid_until=NOW + timedelta(hours=1),
    )

    before = evaluate_scope("https://example.com/", scope, at=NOW - timedelta(seconds=1))
    expired = evaluate_scope("https://example.com/", scope, at=NOW + timedelta(hours=1))

    assert before.reason == "engagement_not_started"
    assert expired.reason == "engagement_expired"


def test_scope_defaults_to_denial_without_allowed_hosts_or_networks() -> None:
    scope = EngagementScope.create()

    decision = evaluate_scope("https://example.com/", scope, at=NOW)

    assert not decision.allowed
    assert decision.reason == "host_not_allowed"
