"""Contracts for deterministic Planner/Operator/Verifier automation."""

from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator

from vuln_proof_claw.automation.mutations import MutationLocation, MutationStrategy
from vuln_proof_claw.automation.security_checks import CheckOutcome, SecurityCheck
from vuln_proof_claw.domain.enums import ActionState, RiskLevel


class MutationCreate(BaseModel):
    model_config = ConfigDict(extra="forbid")

    location: MutationLocation
    name: str = Field(min_length=1, max_length=128)
    strategy: MutationStrategy
    original_value: str | None = Field(default=None, max_length=256)
    replacement_value: str | None = Field(default=None, max_length=256)


class AutomationPlanCreate(BaseModel):
    model_config = ConfigDict(extra="forbid")

    target: str = Field(min_length=1, max_length=2048)
    checks: tuple[SecurityCheck, ...] = (
        SecurityCheck.CORS,
        SecurityCheck.AUTHENTICATION,
        SecurityCheck.AUTHORIZATION,
        SecurityCheck.INPUT_VALIDATION,
    )
    mutations: tuple[MutationCreate, ...] = ()
    review_reason: str = Field(default="Reviewed bounded security validation", max_length=1000)

    @field_validator("checks")
    @classmethod
    def unique_checks(cls, value: tuple[SecurityCheck, ...]) -> tuple[SecurityCheck, ...]:
        if not value:
            raise ValueError("at least one security check is required")
        return tuple(dict.fromkeys(value))


class PlannedActionSummary(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    check: SecurityCheck
    task_id: str
    action_id: str
    action_type: str
    risk_level: RiskLevel
    state: ActionState
    parameter_digest: str


class AutomationPlanSummary(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    schema_version: Literal["v1"] = "v1"
    flow_id: str
    engagement_id: str
    planner: str
    operator: str
    verifier: str
    mutation_plan_digest: str | None
    actions: tuple[PlannedActionSummary, ...]


class ObservationInput(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    status_code: int = Field(ge=100, le=599)
    headers: dict[str, str] = Field(default_factory=dict)
    body_digest: str = Field(pattern=r"^[a-f0-9]{64}$")
    body_size: int = Field(ge=0)


class VerificationCreate(BaseModel):
    model_config = ConfigDict(extra="forbid")

    check: SecurityCheck
    baseline: ObservationInput
    comparison: ObservationInput | None = None
    supplied_origin: str | None = Field(default=None, max_length=2048)


class VerificationSummary(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    schema_version: Literal["v1"] = "v1"
    check: SecurityCheck
    outcome: CheckOutcome
    reason: str
    evidence: tuple[str, ...]
    verifier: Literal["deterministic-verifier-v1"] = "deterministic-verifier-v1"
