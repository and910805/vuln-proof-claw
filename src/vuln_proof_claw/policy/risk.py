"""Deterministic action risk classification."""

from __future__ import annotations

import re
from types import MappingProxyType
from typing import Final

from vuln_proof_claw.domain.enums import RiskLevel
from vuln_proof_claw.domain.errors import DomainValidationError

_ACTION_SEPARATOR = re.compile(r"[\s-]+")

ACTION_RISK_LEVELS: Final = MappingProxyType(
    {
        "public_page_read": RiskLevel.L0,
        "robots_read": RiskLevel.L0,
        "passive_fingerprint": RiskLevel.L0,
        "directory_enumeration": RiskLevel.L1,
        "port_scan": RiskLevel.L1,
        "active_api_probe": RiskLevel.L1,
        "exploit_attempt": RiskLevel.L2,
        "password_test": RiskLevel.L2,
        "file_upload": RiskLevel.L2,
        "post_exploitation": RiskLevel.L3,
        "privilege_escalation": RiskLevel.L3,
        "lateral_movement": RiskLevel.L3,
        "data_modification": RiskLevel.L4,
        "data_deletion": RiskLevel.L4,
        "persistence": RiskLevel.L4,
        "destructive_operation": RiskLevel.L4,
    }
)

PERMANENT_DENY_ACTIONS: Final = frozenset(
    {
        "cover_tracks",
        "disable_security_controls",
        "self_propagation",
        "unbounded_targeting",
    }
)


def normalize_action_type(value: str) -> str:
    """Normalize an action type for deterministic policy lookup."""
    normalized = _ACTION_SEPARATOR.sub("_", value.strip().lower())
    if not normalized:
        raise DomainValidationError("action_type must not be empty")
    if not all(character.isalnum() or character == "_" for character in normalized):
        raise DomainValidationError("action_type contains an invalid character")
    return normalized


def classify_risk(action_type: str) -> RiskLevel:
    """Classify known actions and conservatively default unknown actions to L2."""
    return ACTION_RISK_LEVELS.get(normalize_action_type(action_type), RiskLevel.L2)


def is_permanently_denied(action_type: str) -> bool:
    """Return whether the system policy always denies the action type."""
    return normalize_action_type(action_type) in PERMANENT_DENY_ACTIONS
