"""The Planner contract and a deterministic Phase 1 implementation.

A plan is a proposal, never an authorization. Whatever produces it — the deterministic
planner here or a model-backed planner later — its output is re-derived and re-checked
before anything runs:

* the risk level is recomputed from the action type and a mismatch is rejected;
* the target is renormalized and re-evaluated against the live engagement scope;
* the policy engine makes the final allow, approve, or deny decision.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Protocol, runtime_checkable
from urllib.parse import urlsplit

from vuln_proof_claw.domain.autonomous import Lead, Mission
from vuln_proof_claw.domain.enums import RiskLevel
from vuln_proof_claw.domain.errors import DomainValidationError
from vuln_proof_claw.policy.risk import classify_risk, is_permanently_denied
from vuln_proof_claw.policy.scope import normalize_query, normalize_target

_MAXIMUM_SUMMARY_LENGTH = 2000


@dataclass(frozen=True, slots=True)
class ProposedAction:
    """The concrete operation a plan asks to perform.

    ``target`` is query-free; a query travels in its own field so that scope and
    approval bind to the path while the digest still covers the exact parameters.
    """

    action_type: str
    target: str
    parameters: tuple[tuple[str, str], ...] = ()
    query: str = ""

    def __post_init__(self) -> None:
        if not self.action_type.strip():
            raise DomainValidationError("action_type must not be empty")
        if not self.target.strip():
            raise DomainValidationError("target must not be empty")


@dataclass(frozen=True, slots=True)
class ResearchPlan:
    """A structured, auditable proposal for one investigative step.

    The fields mirror the questions a planner must answer before acting: what is known,
    what contradicts the hypothesis, what is proposed, and what result would confirm or
    reject it.
    """

    lead_id: str
    objective: str
    hypothesis: str
    proposed_action: ProposedAction
    expected_observation: str
    reason: str
    success_condition: str
    failure_condition: str
    risk_level: RiskLevel
    known_evidence: tuple[str, ...] = field(default_factory=tuple)
    contradicting_evidence: tuple[str, ...] = field(default_factory=tuple)

    def __post_init__(self) -> None:
        for name in (
            "lead_id",
            "objective",
            "hypothesis",
            "expected_observation",
            "reason",
            "success_condition",
            "failure_condition",
        ):
            value = str(getattr(self, name))
            if not value.strip():
                raise DomainValidationError(f"{name} must not be empty")
            if len(value) > _MAXIMUM_SUMMARY_LENGTH:
                raise DomainValidationError(f"{name} exceeds the maximum length")


@dataclass(frozen=True, slots=True)
class PlanRejection:
    """Why a proposed plan was refused before it reached the policy engine."""

    reason: str


@runtime_checkable
class Planner(Protocol):
    """Produce the next investigative step for a lead.

    Implementations must be free of side effects: a planner proposes, it never acts.
    """

    def plan(self, lead: Lead, *, mission: Mission) -> ResearchPlan | None:
        """Return the next step for a lead, or None when nothing is worth doing."""
        ...


def validate_plan(plan: ResearchPlan, *, mission: Mission) -> PlanRejection | None:
    """Re-derive a plan's safety properties and reject any inconsistency.

    This runs before the policy engine and exists to make a dishonest or malformed plan
    fail loudly rather than be silently corrected. The policy engine is still the
    authority; this is defense in depth.
    """
    if is_permanently_denied(plan.proposed_action.action_type):
        return PlanRejection(reason="system_permanent_deny")

    classified = classify_risk(plan.proposed_action.action_type)
    if plan.risk_level is not classified:
        return PlanRejection(reason="risk_classification_mismatch")

    ceiling = mission.maximum_autonomous_risk
    if _risk_rank(classified) > _risk_rank(ceiling):
        return PlanRejection(reason="risk_exceeds_autonomous_ceiling")

    try:
        normalized = normalize_target(plan.proposed_action.target)
    except DomainValidationError:
        return PlanRejection(reason="target_not_normalizable")
    if str(normalized) != plan.proposed_action.target:
        return PlanRejection(reason="target_not_normalized")
    return None


def _risk_rank(level: RiskLevel) -> int:
    return int(level.value[1])


class DeterministicPlanner:
    """A Phase 1 planner that proposes only passive, evidence-gathering reads.

    It makes no model calls. Given a lead that names a concrete target, it proposes a
    single bounded read whose purpose is to collect the evidence the Verifier needs. It
    never proposes anything above the mission's autonomous risk ceiling.
    """

    def __init__(self, *, action_type: str = "public_page_read") -> None:
        self._action_type = action_type
        self._risk_level = classify_risk(action_type)

    def plan(self, lead: Lead, *, mission: Mission) -> ResearchPlan | None:
        target = lead.next_action
        if not target:
            return None
        try:
            normalized = str(normalize_target(target))
            query = normalize_query(urlsplit(target).query)
        except DomainValidationError:
            return None
        if _risk_rank(self._risk_level) > _risk_rank(mission.maximum_autonomous_risk):
            return None

        return ResearchPlan(
            lead_id=lead.id,
            objective=f"Collect evidence for: {lead.title}",
            hypothesis=lead.hypothesis,
            proposed_action=ProposedAction(
                action_type=self._action_type,
                target=normalized,
                query=query,
            ),
            expected_observation=(
                "A bounded HTTP response whose status, headers, and body size can be "
                "compared against previously recorded observations for this target."
            ),
            reason=(
                "The lead names a concrete in-scope target and has no recorded "
                "observation for the current attack-surface state."
            ),
            success_condition=(
                "A response is captured and differs materially from the recorded baseline."
            ),
            failure_condition=(
                "The response matches the recorded baseline, or the target is unreachable."
            ),
            risk_level=self._risk_level,
            known_evidence=tuple(lead.evidence_ids),
        )


__all__ = [
    "DeterministicPlanner",
    "PlanRejection",
    "Planner",
    "ProposedAction",
    "ResearchPlan",
    "validate_plan",
]
