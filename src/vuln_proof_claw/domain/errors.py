"""Domain-specific errors."""

from __future__ import annotations

from vuln_proof_claw.domain.enums import ActionState


class DomainError(Exception):
    """Base class for expected domain failures."""


class DomainValidationError(DomainError, ValueError):
    """Raised when a domain value violates an invariant."""


class InvalidActionTransitionError(DomainError):
    """Raised when an action state transition is not allowed."""

    def __init__(self, current: ActionState, target: ActionState) -> None:
        self.current = current
        self.target = target
        super().__init__(f"cannot transition action from {current.value} to {target.value}")


class ApprovalRequiredError(DomainError):
    """Raised when a risk-bearing action has no bound approval."""

    def __init__(self) -> None:
        super().__init__("explicit approval is required before this action can be queued")


class InvalidApprovalError(DomainError):
    """Raised when an approval does not authorize the exact action."""

    def __init__(self) -> None:
        super().__init__("approval is expired, exhausted, or does not match the action")
