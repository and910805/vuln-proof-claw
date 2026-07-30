"""Tests for deterministic canonical metadata encoding."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from enum import StrEnum

import pytest

from vuln_proof_claw.domain.errors import DomainValidationError
from vuln_proof_claw.evidence.canonical import canonical_json, freeze_canonical


class ExampleValue(StrEnum):
    VALUE = "value"


def test_canonical_json_is_independent_of_mapping_order() -> None:
    first = {"z": [3, 2, 1], "a": {"enabled": True, "value": None}}
    second = {"a": {"value": None, "enabled": True}, "z": [3, 2, 1]}

    assert canonical_json(first) == canonical_json(second)
    assert canonical_json(first) == b'{"a":{"enabled":true,"value":null},"z":[3,2,1]}'


def test_canonical_json_normalizes_unicode_datetime_and_enum() -> None:
    decomposed = "e\u0301"
    local_time = datetime(2026, 7, 30, 20, 0, tzinfo=timezone(timedelta(hours=8)))

    encoded = canonical_json(
        {
            "text": decomposed,
            "captured_at": local_time,
            "enum": ExampleValue.VALUE,
        }
    )

    assert encoded.decode() == (
        '{"captured_at":"2026-07-30T12:00:00.000000Z","enum":"value","text":"é"}'
    )


def test_freeze_canonical_prevents_nested_mapping_mutation() -> None:
    original = {"nested": {"value": "before"}}
    frozen = freeze_canonical(original)
    original["nested"]["value"] = "after"

    assert canonical_json(frozen) == b'{"nested":{"value":"before"}}'


@pytest.mark.parametrize(
    "value",
    [
        1.5,
        float("nan"),
        b"bytes",
        {"unordered"},
        {1: "non-string key"},
        1 << 64,
        datetime(2026, 7, 30),
    ],
)
def test_rejects_noncanonical_metadata(value: object) -> None:
    with pytest.raises(DomainValidationError):
        canonical_json(value)
