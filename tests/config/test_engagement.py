"""Tests for operator-authored engagement definitions."""

from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path

import pytest

from vuln_proof_claw.config.engagement import (
    EngagementDefinitionError,
    load_engagement_definition,
    parse_engagement_definition,
)
from vuln_proof_claw.policy.scope import evaluate_scope

NOW = datetime(2026, 11, 1, tzinfo=UTC)

MINIMAL = """
name: example-program
project: Example Inc
starts_at: 2026-10-01T00:00:00Z
ends_at: 2026-12-31T00:00:00Z
scope:
  include: ["api.example.com"]
program:
  program_name: Example Bug Bounty
"""


def definition(body: str) -> str:
    return body.strip() + "\n"


def test_a_minimal_definition_parses_and_normalizes() -> None:
    parsed = parse_engagement_definition(definition(MINIMAL))

    assert parsed.name == "example-program"
    assert parsed.program.program_name == "Example Bug Bounty"
    assert parsed.risk_policy.maximum_autonomous_risk.value == "L1"


def test_wildcards_are_separated_from_exact_hostnames() -> None:
    parsed = parse_engagement_definition(
        definition(
            """
name: example-program
project: Example Inc
starts_at: 2026-10-01T00:00:00Z
ends_at: 2026-12-31T00:00:00Z
scope:
  include: ["*.example.com", "api.example.com"]
  exclude: ["status.example.com", "*.thirdparty.example"]
program:
  program_name: Example Bug Bounty
"""
        )
    )
    scope = parsed.as_engagement_scope()

    assert scope.allowed_wildcards == frozenset({"*.example.com"})
    assert scope.allowed_hostnames == frozenset({"api.example.com"})
    assert scope.denied_wildcards == frozenset({"*.thirdparty.example"})
    assert scope.denied_hostnames == frozenset({"status.example.com"})


def test_the_resolved_scope_enforces_the_written_authorization() -> None:
    parsed = parse_engagement_definition(
        definition(
            """
name: example-program
project: Example Inc
starts_at: 2026-10-01T00:00:00Z
ends_at: 2026-12-31T00:00:00Z
scope:
  include: ["*.example.com"]
  exclude: ["status.example.com"]
program:
  program_name: Example Bug Bounty
"""
        )
    )
    scope = parsed.as_engagement_scope()

    assert evaluate_scope("https://api.example.com/", scope, at=NOW).allowed
    assert not evaluate_scope("https://status.example.com/", scope, at=NOW).allowed
    assert not evaluate_scope("https://example.com/", scope, at=NOW).allowed
    assert not evaluate_scope("https://other.test/", scope, at=NOW).allowed


def test_a_definition_outside_its_window_is_denied() -> None:
    parsed = parse_engagement_definition(definition(MINIMAL))
    scope = parsed.as_engagement_scope()

    early = evaluate_scope("https://api.example.com/", scope, at=datetime(2026, 1, 1, tzinfo=UTC))
    late = evaluate_scope("https://api.example.com/", scope, at=datetime(2027, 1, 1, tzinfo=UTC))

    assert early.reason == "engagement_not_started"
    assert late.reason == "engagement_expired"


def test_a_definition_must_authorize_at_least_one_target() -> None:
    with pytest.raises(EngagementDefinitionError):
        parse_engagement_definition(
            definition(
                """
name: example-program
project: Example Inc
starts_at: 2026-10-01T00:00:00Z
ends_at: 2026-12-31T00:00:00Z
scope:
  include: []
program:
  program_name: Example Bug Bounty
"""
            )
        )


def test_destructive_risk_cannot_be_authorized_in_a_definition() -> None:
    with pytest.raises(EngagementDefinitionError):
        parse_engagement_definition(
            definition(
                MINIMAL
                + """
risk_policy:
  maximum_risk: L4
"""
            )
        )


def test_autonomous_risk_above_l1_is_refused() -> None:
    with pytest.raises(EngagementDefinitionError):
        parse_engagement_definition(
            definition(
                MINIMAL
                + """
risk_policy:
  maximum_autonomous_risk: L2
"""
            )
        )


def test_unknown_keys_are_refused_rather_than_ignored() -> None:
    with pytest.raises(EngagementDefinitionError):
        parse_engagement_definition(definition(MINIMAL + "\nunexpected_key: true\n"))


def test_malformed_documents_are_rejected() -> None:
    with pytest.raises(EngagementDefinitionError):
        parse_engagement_definition("just a string")
    with pytest.raises(EngagementDefinitionError):
        parse_engagement_definition("name: [unclosed\n")


def test_an_oversized_definition_is_refused() -> None:
    with pytest.raises(EngagementDefinitionError):
        parse_engagement_definition("#" + "a" * (1024 * 1024))


def test_naive_timestamps_are_refused() -> None:
    with pytest.raises(EngagementDefinitionError):
        parse_engagement_definition(
            definition(
                """
name: example-program
project: Example Inc
starts_at: 2026-10-01T00:00:00
ends_at: 2026-12-31T00:00:00
scope:
  include: ["api.example.com"]
program:
  program_name: Example Bug Bounty
"""
            )
        )


def test_the_shipped_example_definition_is_valid() -> None:
    parsed = load_engagement_definition(Path("examples/engagement.yaml"))
    scope = parsed.as_engagement_scope()

    assert parsed.program.program_name == "Example Bug Bounty"
    assert parsed.as_budget().requests_per_minute_per_domain == 5
    assert parsed.as_cadence().cycle_interval_seconds == 300
    assert evaluate_scope("https://api.example.com/", scope, at=NOW).allowed


def test_a_missing_file_is_reported_rather_than_raised_raw(tmp_path: Path) -> None:
    with pytest.raises(EngagementDefinitionError):
        load_engagement_definition(tmp_path / "absent.yaml")
