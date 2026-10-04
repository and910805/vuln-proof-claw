"""Deterministic request and token budgets for autonomous missions.

Every ceiling is evaluated before an action is proposed, never after it executes. A
budget refusal pauses the affected work and is recorded; it never silently drops a lead.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime
from enum import StrEnum

from sqlalchemy.orm import Session

from vuln_proof_claw.domain.autonomous import Mission
from vuln_proof_claw.domain.errors import DomainValidationError
from vuln_proof_claw.persistence.autonomous_repositories import (
    BudgetLedgerRepository,
    BudgetUsage,
    BudgetWindow,
)

_EPOCH = datetime(1970, 1, 1, tzinfo=UTC)


class BudgetWindowKind(StrEnum):
    """Accounting windows tracked in the budget ledger."""

    MINUTE = "minute"
    HOUR = "hour"
    DAY = "day"
    TOTAL = "total"


@dataclass(frozen=True, slots=True)
class BudgetDecision:
    """Auditable result of a budget check."""

    allowed: bool
    reason: str

    def __bool__(self) -> bool:
        return self.allowed


def window_start(kind: BudgetWindowKind, at: datetime) -> datetime:
    """Return the deterministic start of the accounting window containing ``at``."""
    if at.tzinfo is None or at.utcoffset() is None:
        raise DomainValidationError("at must be timezone-aware")
    moment = at.astimezone(UTC)
    if kind is BudgetWindowKind.MINUTE:
        return moment.replace(second=0, microsecond=0)
    if kind is BudgetWindowKind.HOUR:
        return moment.replace(minute=0, second=0, microsecond=0)
    if kind is BudgetWindowKind.DAY:
        return moment.replace(hour=0, minute=0, second=0, microsecond=0)
    return _EPOCH


class BudgetGate:
    """Enforce per-domain rate limits and mission request and token ceilings."""

    def __init__(self, session: Session, mission: Mission) -> None:
        self._mission = mission
        self._ledger = BudgetLedgerRepository(session)

    def permits_request(self, *, host: str, at: datetime) -> BudgetDecision:
        """Return whether one more target-facing request is within every ceiling."""
        budget = self._mission.budget
        checks = (
            (
                BudgetWindowKind.MINUTE,
                host,
                budget.requests_per_minute_per_domain,
                "domain_rate_limit_reached",
            ),
            (BudgetWindowKind.HOUR, "", budget.requests_per_hour, "hourly_request_ceiling_reached"),
            (BudgetWindowKind.DAY, "", budget.requests_per_day, "daily_request_ceiling_reached"),
            (BudgetWindowKind.TOTAL, "", budget.total_requests, "mission_request_budget_exhausted"),
        )
        for kind, scope_key, ceiling, reason in checks:
            window = BudgetWindow(kind.value, window_start(kind, at), scope_key)
            if self._ledger.usage(self._mission.id, window).requests >= ceiling:
                return BudgetDecision(allowed=False, reason=reason)
        return BudgetDecision(allowed=True, reason="within_budget")

    def record_request(self, *, host: str, at: datetime) -> None:
        """Record one consumed request against every applicable window."""
        usage = BudgetUsage(requests=1)
        for kind, scope_key in (
            (BudgetWindowKind.MINUTE, host),
            (BudgetWindowKind.HOUR, ""),
            (BudgetWindowKind.DAY, ""),
            (BudgetWindowKind.TOTAL, ""),
        ):
            window = BudgetWindow(kind.value, window_start(kind, at), scope_key)
            self._ledger.consume(self._mission.id, window, usage)

    def permits_tokens(self, *, tokens: int, lead_key: str, at: datetime) -> BudgetDecision:
        """Return whether a model call of ``tokens`` fits the daily and per-lead budgets."""
        if tokens < 0:
            raise DomainValidationError("tokens must not be negative")
        budget = self._mission.budget
        daily = BudgetWindow(
            BudgetWindowKind.DAY.value, window_start(BudgetWindowKind.DAY, at), "llm"
        )
        if self._ledger.usage(self._mission.id, daily).tokens + tokens > budget.llm_tokens_per_day:
            return BudgetDecision(allowed=False, reason="daily_token_budget_exhausted")
        per_lead = BudgetWindow(BudgetWindowKind.TOTAL.value, _EPOCH, f"lead:{lead_key}")
        used = self._ledger.usage(self._mission.id, per_lead).tokens
        if used + tokens > budget.llm_tokens_per_lead:
            return BudgetDecision(allowed=False, reason="lead_token_budget_exhausted")
        return BudgetDecision(allowed=True, reason="within_budget")

    def record_tokens(self, *, tokens: int, lead_key: str, at: datetime) -> None:
        """Record consumed model tokens against the daily and per-lead budgets."""
        if tokens < 0:
            raise DomainValidationError("tokens must not be negative")
        usage = BudgetUsage(tokens=tokens)
        daily = BudgetWindow(
            BudgetWindowKind.DAY.value, window_start(BudgetWindowKind.DAY, at), "llm"
        )
        self._ledger.consume(self._mission.id, daily, usage)
        per_lead = BudgetWindow(BudgetWindowKind.TOTAL.value, _EPOCH, f"lead:{lead_key}")
        self._ledger.consume(self._mission.id, per_lead, usage)


__all__ = [
    "BudgetDecision",
    "BudgetGate",
    "BudgetWindowKind",
    "window_start",
]
