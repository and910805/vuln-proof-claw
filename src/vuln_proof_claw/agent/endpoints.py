"""Classify endpoints by what probing them would do to the target.

An autonomous prober needs to answer one question before it touches anything: *if I
call this, what happens?* A human researcher answers it by reading the name —
``getUserMenuList`` is safe to call, ``setDeviceSecureWipe`` obviously is not. This
module encodes that reading so the agent does not need a model to make the call, and
cannot be talked into a different answer.

The classification is deliberately pessimistic. An endpoint that cannot be confidently
placed is treated as mutating, and anything that pattern-matches a destructive verb is
never probed automatically regardless of what else it looks like. Being wrong in the
cautious direction costs a missed finding; being wrong in the other direction can wipe
somebody's device.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from enum import StrEnum
from typing import Final

from vuln_proof_claw.domain.errors import DomainValidationError

_READ_METHODS: Final = frozenset({"GET", "HEAD", "OPTIONS"})

#: Verbs whose effect cannot be undone, or whose effect weakens a security control.
#: Matched before anything else and never probed automatically.
_DESTRUCTIVE: Final = re.compile(
    r"wipe|erase|destroy|purge|truncate|format|"
    r"delete|remove|drop|revoke|reset|"
    r"disable|deactivate|suspend|lock|"
    r"shutdown|reboot|restart|poweroff|"
    r"factory|restore|rollback|"
    r"bios|firmware|boot|"
    r"batch",
    re.IGNORECASE,
)

#: Verbs that change state recoverably.
_MUTATING: Final = re.compile(
    r"set|update|create|add|insert|put|patch|post|"
    r"save|store|write|upload|import|send|assign|"
    r"enable|activate|register|invite|generate|issue",
    re.IGNORECASE,
)

#: Verbs that only read. Checked last so a name like ``getOrDeleteX`` lands on the
#: destructive branch rather than the read one.
_READ: Final = re.compile(
    r"get|list|query|search|find|fetch|read|view|show|"
    r"export|download|report|detail|info|status|check|verify",
    re.IGNORECASE,
)


class EndpointRisk(StrEnum):
    """What probing an endpoint would do."""

    READ = "read"
    MUTATING = "mutating"
    DESTRUCTIVE = "destructive"

    @property
    def probeable_automatically(self) -> bool:
        """Return whether an unattended agent may call this at all."""
        return self is not EndpointRisk.DESTRUCTIVE


class ProbeStrategy(StrEnum):
    """How an endpoint may be probed without changing the target."""

    DIRECT = "direct"
    """Call it as intended. Only for reads."""

    EMPTY_BODY = "empty_body"
    """Send a deliberately incomplete request.

    A mutating endpoint given no parameters fails in its own validation layer before
    doing anything. That still reveals whether an authentication check runs *before*
    the business logic, which is the question worth asking, while changing nothing.
    """

    REFUSE = "refuse"
    """Do not call it. Record it as requiring a human decision."""


@dataclass(frozen=True, slots=True)
class EndpointClassification:
    """Why an endpoint was placed where it was."""

    method: str
    path: str
    risk: EndpointRisk
    strategy: ProbeStrategy
    reason: str

    @property
    def safe_to_probe(self) -> bool:
        return self.strategy is not ProbeStrategy.REFUSE

    def as_summary(self) -> str:
        return f"[{self.risk.value:<11}] {self.method:<6} {self.path} — {self.reason}"


def _matched(pattern: re.Pattern[str], value: str) -> str | None:
    found = pattern.search(value)
    return found.group(0).lower() if found else None


def classify_endpoint(method: str, path: str) -> EndpointClassification:
    """Decide what probing this endpoint would do.

    Order matters. A destructive verb anywhere in the path wins, even when the method
    is a read and even when a read verb also appears: ``GET /api/resetToken`` is not a
    read just because it is a GET.
    """
    if not method.strip():
        raise DomainValidationError("method must not be empty")
    if not path.startswith("/"):
        raise DomainValidationError("path must be absolute")

    normalized_method = method.upper()
    destructive = _matched(_DESTRUCTIVE, path)
    if destructive:
        return EndpointClassification(
            method=normalized_method,
            path=path,
            risk=EndpointRisk.DESTRUCTIVE,
            strategy=ProbeStrategy.REFUSE,
            reason=f"path contains the destructive verb '{destructive}'",
        )

    mutating = _matched(_MUTATING, path)
    if mutating:
        return EndpointClassification(
            method=normalized_method,
            path=path,
            risk=EndpointRisk.MUTATING,
            strategy=ProbeStrategy.EMPTY_BODY,
            reason=f"path contains the state-changing verb '{mutating}'",
        )

    read_method = normalized_method in _READ_METHODS
    read = _matched(_READ, path)

    if read:
        # The name says it reads. Many APIs expose reads over POST by convention, so
        # the risk follows the name while the strategy still follows the method: a POST
        # may have side effects the name does not advertise, so it is probed with an
        # empty body until something establishes otherwise.
        return EndpointClassification(
            method=normalized_method,
            path=path,
            risk=EndpointRisk.READ,
            strategy=ProbeStrategy.DIRECT if read_method else ProbeStrategy.EMPTY_BODY,
            reason=(
                f"read verb '{read}'"
                + ("" if read_method else f" exposed over {normalized_method}")
            ),
        )

    if not read_method:
        return EndpointClassification(
            method=normalized_method,
            path=path,
            risk=EndpointRisk.MUTATING,
            strategy=ProbeStrategy.EMPTY_BODY,
            reason=f"{normalized_method} with no recognised verb is assumed to write",
        )

    return EndpointClassification(
        method=normalized_method,
        path=path,
        risk=EndpointRisk.READ,
        strategy=ProbeStrategy.DIRECT,
        reason="read method with no state-changing verb",
    )


def classify_all(
    endpoints: tuple[tuple[str, str], ...],
) -> tuple[EndpointClassification, ...]:
    """Classify a whole inventory, preserving order."""
    return tuple(classify_endpoint(method, path) for method, path in endpoints)


def probeable(
    classifications: tuple[EndpointClassification, ...],
) -> tuple[EndpointClassification, ...]:
    """Return only the endpoints an unattended agent may call."""
    return tuple(item for item in classifications if item.safe_to_probe)


def refused(
    classifications: tuple[EndpointClassification, ...],
) -> tuple[EndpointClassification, ...]:
    """Return the endpoints that need a human decision.

    These are not dropped. They are the most interesting endpoints on the target, and
    an operator should see them listed with the reason they were held back.
    """
    return tuple(item for item in classifications if not item.safe_to_probe)


__all__ = [
    "EndpointClassification",
    "EndpointRisk",
    "ProbeStrategy",
    "classify_all",
    "classify_endpoint",
    "probeable",
    "refused",
]
