"""Tests for opaque, sortable domain identifiers."""

from uuid import UUID

import pytest

from vuln_proof_claw.domain.identifiers import ContextIdentifiers, new_identifier, uuid7


def test_uuid7_has_expected_version_variant_and_timestamp() -> None:
    identifier = uuid7(timestamp_ms=1_900_000_000_000)

    assert identifier.version == 7
    assert identifier.variant == "specified in RFC 4122"
    assert identifier.int >> 80 == 1_900_000_000_000


def test_uuid7_is_monotonic_within_one_process() -> None:
    identifiers = [uuid7() for _ in range(100)]

    assert identifiers == sorted(identifiers)
    assert len(set(identifiers)) == len(identifiers)


def test_new_identifier_is_an_opaque_uuid() -> None:
    value = new_identifier()

    assert UUID(value).version == 7
    assert "@" not in value


def test_invalid_uuid7_timestamp_is_rejected() -> None:
    with pytest.raises(ValueError, match="48-bit"):
        uuid7(timestamp_ms=-1)


def test_context_identifiers_omit_unset_values() -> None:
    identifiers = ContextIdentifiers(request_id="req", action_id="action")

    assert identifiers.as_log_context() == {
        "request_id": "req",
        "action_id": "action",
    }
