"""Differential authorization testing with deterministic oracles.

This module is the system's answer to hallucination. Nothing here consults a language
model. A probe records what a server actually returned; an oracle is a pure function
over those recordings. A verdict is therefore reproducible by anyone holding the same
probes, and can be recomputed from the evidence chain without rerunning the test.

The division of labour is deliberate:

* A model may propose *what to test* and may later explain *why a confirmed difference
  matters*.
* Only code decides *whether a difference exists*.

Oracles are written to be conservative. Every rule has explicit suppression conditions
for the benign explanations that would otherwise produce false positives, because a
confident false report costs more than a missed one: under the activity rules an
unverified report burns one of only two 補正 opportunities.
"""

from __future__ import annotations

import hashlib
from collections.abc import Sequence
from dataclasses import dataclass, field
from datetime import datetime
from enum import StrEnum
from typing import Final

from vuln_proof_claw.domain.errors import DomainValidationError

ANONYMOUS: Final = "anonymous"

_SUCCESS_MIN: Final = 200
_SUCCESS_MAX: Final = 299
_REDIRECT_MIN: Final = 300
_REDIRECT_MAX: Final = 399
_DENIED_STATUSES: Final = frozenset({401, 403})
_NOT_FOUND: Final = 404
_MINIMUM_BODY_BYTES: Final = 32
_SIMILARITY_THRESHOLD: Final = 0.98


class IdentityRole(StrEnum):
    """The privilege tier an identity represents within one engagement."""

    ANONYMOUS = "anonymous"
    USER = "user"
    PRIVILEGED = "privileged"

    @property
    def rank(self) -> int:
        return {"anonymous": 0, "user": 1, "privileged": 2}[self.value]


@dataclass(frozen=True, slots=True)
class Identity:
    """A test identity. Credentials live elsewhere; this is only its label and tier."""

    name: str
    role: IdentityRole = IdentityRole.USER
    owns: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        if not self.name.strip():
            raise DomainValidationError("identity name must not be empty")


@dataclass(frozen=True, slots=True)
class ProbeResult:
    """What one identity actually received from one endpoint.

    These are recorded facts. No field is inferred, and the body is reduced to a digest
    and a length so that a verdict never depends on anyone's reading of the content.
    """

    identity: str
    method: str
    target: str
    status_code: int
    body_digest: str
    body_size: int
    content_type: str = ""
    location: str = ""
    elapsed_ms: int = 0
    observed_at: datetime | None = None

    def __post_init__(self) -> None:
        for name in ("identity", "method", "target"):
            if not str(getattr(self, name)).strip():
                raise DomainValidationError(f"{name} must not be empty")
        if self.body_size < 0:
            raise DomainValidationError("body_size must not be negative")

    @property
    def succeeded(self) -> bool:
        return _SUCCESS_MIN <= self.status_code <= _SUCCESS_MAX

    @property
    def denied(self) -> bool:
        return self.status_code in _DENIED_STATUSES

    @property
    def redirected(self) -> bool:
        return _REDIRECT_MIN <= self.status_code <= _REDIRECT_MAX

    @property
    def substantive(self) -> bool:
        """Return whether the body is large enough for a match to mean anything."""
        return self.succeeded and self.body_size >= _MINIMUM_BODY_BYTES


def body_digest(content: bytes) -> str:
    """Return the digest a probe records instead of the raw body."""
    return hashlib.sha256(content).hexdigest()


class OracleRule(StrEnum):
    """The deterministic checks this module can make."""

    UNAUTHENTICATED_ACCESS = "unauthenticated_access"
    HORIZONTAL_PRIVILEGE = "horizontal_privilege"
    VERTICAL_PRIVILEGE = "vertical_privilege"
    DENIAL_INCONSISTENCY = "denial_inconsistency"


@dataclass(frozen=True, slots=True)
class OracleVerdict:
    """A computed judgement about one endpoint.

    ``triggered`` is the output of a pure function over probes. ``suppressed_by`` names
    the benign explanation when a surface-level difference was deliberately not
    reported, so a reviewer can see the rule considered it.
    """

    rule: OracleRule
    triggered: bool
    target: str
    reason: str
    probes: tuple[ProbeResult, ...] = field(default_factory=tuple)
    suppressed_by: str | None = None

    def __bool__(self) -> bool:
        return self.triggered

    def as_summary(self) -> str:
        state = "TRIGGERED" if self.triggered else "clear"
        detail = self.suppressed_by or self.reason
        return f"[{state}] {self.rule.value} {self.target} — {detail}"


def _target_of(*candidates: ProbeResult | None) -> str:
    """Return the target from whichever probe is present."""
    for probe in candidates:
        if probe is not None:
            return probe.target
    return "?"


def _find(probes: Sequence[ProbeResult], identity: str) -> ProbeResult | None:
    for probe in probes:
        if probe.identity == identity:
            return probe
    return None


def check_unauthenticated_access(
    probes: Sequence[ProbeResult],
    *,
    authenticated: str,
) -> OracleVerdict:
    """Decide whether an anonymous caller receives the authenticated response.

    Suppressed when the endpoint is simply public: if anonymous and authenticated both
    succeed with identical bodies, that is only a finding if the content is actually
    privileged, which this rule cannot know. It therefore reports only the narrower,
    checkable case — anonymous succeeds where the server also serves real content.
    """
    anonymous = _find(probes, ANONYMOUS)
    user = _find(probes, authenticated)
    target = _target_of(anonymous, user)

    if anonymous is None or user is None:
        return OracleVerdict(
            OracleRule.UNAUTHENTICATED_ACCESS,
            triggered=False,
            target=target,
            reason="missing probe for anonymous or authenticated identity",
        )
    if not anonymous.succeeded:
        return OracleVerdict(
            OracleRule.UNAUTHENTICATED_ACCESS,
            triggered=False,
            target=target,
            reason=f"anonymous received {anonymous.status_code}",
        )
    if not anonymous.substantive:
        return OracleVerdict(
            OracleRule.UNAUTHENTICATED_ACCESS,
            triggered=False,
            target=target,
            reason="anonymous body too small to be meaningful",
            suppressed_by="empty_or_tiny_body",
        )
    if anonymous.body_digest != user.body_digest:
        return OracleVerdict(
            OracleRule.UNAUTHENTICATED_ACCESS,
            triggered=False,
            target=target,
            reason="anonymous body differs from authenticated body",
            suppressed_by="different_content",
        )
    return OracleVerdict(
        OracleRule.UNAUTHENTICATED_ACCESS,
        triggered=True,
        target=target,
        reason=(
            f"anonymous received the same {anonymous.body_size}-byte body as "
            f"{authenticated} (digest {anonymous.body_digest[:16]}…)"
        ),
        probes=(anonymous, user),
    )


def check_horizontal_privilege(
    probes: Sequence[ProbeResult],
    *,
    owner: str,
    other: str,
) -> OracleVerdict:
    """Decide whether one user receives another user's resource.

    This is the strongest signal the module produces, because identical bodies across
    two authenticated identities for an owner-scoped resource have no benign reading.
    Suppressed when anonymous also receives it (the resource is public, not leaked) or
    when the body is too small to distinguish from a shared empty response.
    """
    owner_probe = _find(probes, owner)
    other_probe = _find(probes, other)
    anonymous = _find(probes, ANONYMOUS)
    target = _target_of(owner_probe, other_probe)

    if owner_probe is None or other_probe is None:
        return OracleVerdict(
            OracleRule.HORIZONTAL_PRIVILEGE,
            triggered=False,
            target=target,
            reason="missing probe for owner or other identity",
        )
    if not owner_probe.substantive:
        return OracleVerdict(
            OracleRule.HORIZONTAL_PRIVILEGE,
            triggered=False,
            target=target,
            reason="owner response is not substantive; nothing to leak",
            suppressed_by="owner_response_not_substantive",
        )
    if not other_probe.succeeded:
        return OracleVerdict(
            OracleRule.HORIZONTAL_PRIVILEGE,
            triggered=False,
            target=target,
            reason=f"{other} correctly received {other_probe.status_code}",
        )
    if other_probe.body_digest != owner_probe.body_digest:
        return OracleVerdict(
            OracleRule.HORIZONTAL_PRIVILEGE,
            triggered=False,
            target=target,
            reason=f"{other} received different content from {owner}",
            suppressed_by="different_content",
        )
    if anonymous is not None and anonymous.body_digest == owner_probe.body_digest:
        return OracleVerdict(
            OracleRule.HORIZONTAL_PRIVILEGE,
            triggered=False,
            target=target,
            reason="anonymous receives the same body; resource is public",
            suppressed_by="resource_is_public",
        )
    return OracleVerdict(
        OracleRule.HORIZONTAL_PRIVILEGE,
        triggered=True,
        target=target,
        reason=(
            f"{other} received the identical {owner_probe.body_size}-byte body that "
            f"{owner} received (digest {owner_probe.body_digest[:16]}…)"
        ),
        probes=tuple(p for p in (owner_probe, other_probe, anonymous) if p is not None),
    )


def check_vertical_privilege(
    probes: Sequence[ProbeResult],
    *,
    lower: str,
    higher: str,
) -> OracleVerdict:
    """Decide whether a lower-privileged identity reaches a privileged endpoint.

    Requires the higher identity to have succeeded, so that the endpoint is known to be
    privileged rather than simply broken for everyone.
    """
    low = _find(probes, lower)
    high = _find(probes, higher)
    target = _target_of(low, high)

    if low is None or high is None:
        return OracleVerdict(
            OracleRule.VERTICAL_PRIVILEGE,
            triggered=False,
            target=target,
            reason="missing probe for lower or higher identity",
        )
    if not high.substantive:
        return OracleVerdict(
            OracleRule.VERTICAL_PRIVILEGE,
            triggered=False,
            target=target,
            reason="privileged identity did not get a substantive response",
            suppressed_by="endpoint_not_demonstrably_privileged",
        )
    if not low.succeeded:
        return OracleVerdict(
            OracleRule.VERTICAL_PRIVILEGE,
            triggered=False,
            target=target,
            reason=f"{lower} correctly received {low.status_code}",
        )
    if low.body_digest != high.body_digest:
        return OracleVerdict(
            OracleRule.VERTICAL_PRIVILEGE,
            triggered=False,
            target=target,
            reason=f"{lower} received different content from {higher}",
            suppressed_by="different_content",
        )
    return OracleVerdict(
        OracleRule.VERTICAL_PRIVILEGE,
        triggered=True,
        target=target,
        reason=(
            f"{lower} received the same privileged body as {higher} "
            f"({high.body_size} bytes, digest {high.body_digest[:16]}…)"
        ),
        probes=(low, high),
    )


def check_denial_inconsistency(probes: Sequence[ProbeResult]) -> OracleVerdict:
    """Flag an endpoint that denies some identities but not others inconsistently.

    This is a weaker signal kept separate from the privilege rules: it says the
    authorization surface is uneven and deserves a human look, not that a boundary was
    crossed. It never fires when every identity agrees.
    """
    if len(probes) < 2:  # noqa: PLR2004 - a comparison needs at least two probes
        return OracleVerdict(
            OracleRule.DENIAL_INCONSISTENCY,
            triggered=False,
            target=probes[0].target if probes else "?",
            reason="not enough probes to compare",
        )
    target = probes[0].target
    statuses = {probe.identity: probe.status_code for probe in probes}
    succeeded = {name for name, code in statuses.items() if _SUCCESS_MIN <= code <= _SUCCESS_MAX}
    denied = {name for name, code in statuses.items() if code in _DENIED_STATUSES}
    not_found = {name for name, code in statuses.items() if code == _NOT_FOUND}

    if denied and not_found:
        return OracleVerdict(
            OracleRule.DENIAL_INCONSISTENCY,
            triggered=True,
            target=target,
            reason=(
                f"endpoint returns 401/403 to {sorted(denied)} but 404 to "
                f"{sorted(not_found)}; existence is distinguishable"
            ),
            probes=tuple(probes),
        )
    if succeeded and denied:
        return OracleVerdict(
            OracleRule.DENIAL_INCONSISTENCY,
            triggered=True,
            target=target,
            reason=f"{sorted(succeeded)} succeeded while {sorted(denied)} were denied",
            probes=tuple(probes),
        )
    return OracleVerdict(
        OracleRule.DENIAL_INCONSISTENCY,
        triggered=False,
        target=target,
        reason="all identities received consistent outcomes",
    )


def evaluate_all(
    probes: Sequence[ProbeResult],
    *,
    owner: str,
    other: str | None = None,
    privileged: str | None = None,
) -> tuple[OracleVerdict, ...]:
    """Run every applicable oracle over one endpoint's probes."""
    verdicts = [
        check_unauthenticated_access(probes, authenticated=owner),
        check_denial_inconsistency(probes),
    ]
    if other is not None:
        verdicts.append(check_horizontal_privilege(probes, owner=owner, other=other))
    if privileged is not None:
        verdicts.append(
            check_vertical_privilege(probes, lower=owner, higher=privileged)
        )
    return tuple(verdicts)


__all__ = [
    "ANONYMOUS",
    "Identity",
    "IdentityRole",
    "OracleRule",
    "OracleVerdict",
    "ProbeResult",
    "body_digest",
    "check_denial_inconsistency",
    "check_horizontal_privilege",
    "check_unauthenticated_access",
    "check_vertical_privilege",
    "evaluate_all",
]
