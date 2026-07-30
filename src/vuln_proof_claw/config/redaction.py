"""Secret-safe serialization helpers."""

from __future__ import annotations

import re
from collections.abc import Mapping, Sequence
from typing import Any, Final

from pydantic import SecretBytes, SecretStr

REDACTED: Final = "[REDACTED]"
SENSITIVE_KEY_PARTS: Final = frozenset(
    {
        "api_key",
        "apikey",
        "authorization",
        "cookie",
        "credential",
        "database_url",
        "password",
        "private_key",
        "secret",
        "session",
        "token",
    }
)
BEARER_PATTERN: Final = re.compile(r"(?i)\bBearer\s+[A-Za-z0-9._~+/=-]+")
BASIC_PATTERN: Final = re.compile(r"(?i)\bBasic\s+[A-Za-z0-9+/=]+")


def _normalized_key(value: object) -> str:
    return str(value).strip().lower().replace("-", "_")


def is_sensitive_key(key: object) -> bool:
    """Return whether a mapping key represents protected data."""
    normalized = _normalized_key(key)
    return any(part in normalized for part in SENSITIVE_KEY_PARTS)


def redact_text(value: str) -> str:
    """Remove common inline authorization values from text."""
    return BASIC_PATTERN.sub(f"Basic {REDACTED}", BEARER_PATTERN.sub(f"Bearer {REDACTED}", value))


def redact(value: Any) -> Any:
    """Return a recursively redacted, serialization-safe value."""
    if isinstance(value, (SecretStr, SecretBytes)):
        return REDACTED
    if isinstance(value, Mapping):
        return {
            str(key): REDACTED if is_sensitive_key(key) else redact(item)
            for key, item in value.items()
        }
    if isinstance(value, tuple):
        return tuple(redact(item) for item in value)
    if isinstance(value, Sequence) and not isinstance(value, (str, bytes, bytearray)):
        return [redact(item) for item in value]
    if isinstance(value, str):
        return redact_text(value)
    return value
