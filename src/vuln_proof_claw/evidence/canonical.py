"""Deterministic metadata encoding for evidence hashing."""

from __future__ import annotations

import json
import unicodedata
from collections.abc import Mapping, Sequence
from datetime import UTC, datetime
from enum import Enum
from types import MappingProxyType

from vuln_proof_claw.domain.errors import DomainValidationError

type CanonicalScalar = str | int | bool | None
type CanonicalValue = CanonicalScalar | tuple[CanonicalValue, ...] | Mapping[str, CanonicalValue]
_MIN_INTEGER = -(1 << 63)
_MAX_INTEGER = (1 << 63) - 1


def _normalize_text(value: str) -> str:
    return unicodedata.normalize("NFC", value)


def _freeze_primitive(value: object) -> CanonicalScalar:
    if value is None or isinstance(value, bool):
        return value
    if isinstance(value, str):
        return _normalize_text(value)
    if isinstance(value, int):
        if not _MIN_INTEGER <= value <= _MAX_INTEGER:
            raise DomainValidationError("canonical integers must fit signed 64-bit range")
        return value
    raise DomainValidationError("floating-point values are not canonical evidence metadata")


def freeze_canonical(value: object) -> CanonicalValue:
    """Validate, normalize, and recursively freeze a canonical JSON value."""
    if value is None or isinstance(value, (bool, str, int, float)):
        return _freeze_primitive(value)
    if isinstance(value, datetime):
        if value.tzinfo is None or value.utcoffset() is None:
            raise DomainValidationError("canonical datetime values must be timezone-aware")
        return value.astimezone(UTC).isoformat(timespec="microseconds").replace("+00:00", "Z")
    if isinstance(value, Enum):
        return freeze_canonical(value.value)
    if isinstance(value, Mapping):
        normalized: dict[str, CanonicalValue] = {}
        for key, item in value.items():
            if not isinstance(key, str):
                raise DomainValidationError("canonical object keys must be strings")
            normalized_key = _normalize_text(key)
            if normalized_key in normalized:
                raise DomainValidationError("canonical object contains duplicate normalized keys")
            normalized[normalized_key] = freeze_canonical(item)
        return MappingProxyType(normalized)
    if isinstance(value, Sequence) and not isinstance(value, (str, bytes, bytearray)):
        return tuple(freeze_canonical(item) for item in value)
    raise DomainValidationError(f"unsupported canonical metadata type: {type(value).__name__}")


def _to_json_value(value: CanonicalValue) -> object:
    if isinstance(value, Mapping):
        return {key: _to_json_value(item) for key, item in value.items()}
    if isinstance(value, tuple):
        return [_to_json_value(item) for item in value]
    return value


def canonical_json(value: object) -> bytes:
    """Encode a value as deterministic, compact UTF-8 JSON."""
    frozen = freeze_canonical(value)
    serialized = json.dumps(
        _to_json_value(frozen),
        allow_nan=False,
        ensure_ascii=False,
        separators=(",", ":"),
        sort_keys=True,
    )
    return serialized.encode("utf-8")
