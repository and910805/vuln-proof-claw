"""Approval validation and replay-resistant consumption."""

from __future__ import annotations

from dataclasses import replace
from datetime import datetime

from vuln_proof_claw.domain.errors import InvalidApprovalError
from vuln_proof_claw.domain.models import Action, Approval


def validate_approval(approval: Approval, action: Action, *, at: datetime) -> None:
    """Require an unexpired, unexhausted approval bound to the exact action."""
    if not approval.authorizes(action, at=at):
        raise InvalidApprovalError


def consume_approval(approval: Approval, action: Action, *, at: datetime) -> Approval:
    """Return a copy with one execution consumed after exact-binding validation."""
    validate_approval(approval, action, at=at)
    return replace(approval, consumed_executions=approval.consumed_executions + 1)
