"""Contracts for deterministic Planner/Operator/Verifier automation."""

from __future__ import annotations

from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator

from vuln_proof_claw.automation.mutations import MutationLocation, MutationStrategy
from vuln_proof_claw.automation.security_checks import CheckOutcome, SecurityCheck
from vuln_proof_claw.domain.enums import ActionState, RiskLevel
from vuln_proof_claw.tooling.registry import IntegrationState


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


class ToolCatalogItem(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    name: str
    category: str
    capability: str
    action_type: str
    risk_level: RiskLevel
    integration_state: IntegrationState
    executable: str | None
    installed: bool | None
    requires_approval: bool
    description: str


class ToolCatalogSummary(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    schema_version: Literal["v1"] = "v1"
    tools: tuple[ToolCatalogItem, ...]


class ToolPlanCreate(BaseModel):
    model_config = ConfigDict(extra="forbid")

    tool: str = Field(min_length=1, max_length=64)
    target: str = Field(min_length=1, max_length=2048)
    parameters: dict[str, Any] = Field(default_factory=dict)
    idempotency_key: str = Field(min_length=1, max_length=255)


class ToolPlanSummary(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    schema_version: Literal["v1"] = "v1"
    flow_id: str
    task_id: str
    action_id: str
    engagement_id: str
    tool: str
    capability: str
    action_type: str
    risk_level: RiskLevel
    state: ActionState
    integration_state: IntegrationState
    parameter_digest: str


class AutonomyBudgetInput(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    maximum_steps: int = Field(default=50, ge=1, le=500)
    maximum_tool_calls: int = Field(default=100, ge=1, le=1000)
    maximum_duration_seconds: int = Field(default=3600, ge=30, le=86_400)
    maximum_consecutive_failures: int = Field(default=3, ge=1, le=10)


class AutonomyStepCreate(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    budget: AutonomyBudgetInput = AutonomyBudgetInput()
    steps: int = Field(default=0, ge=0)
    tool_calls: int = Field(default=0, ge=0)
    elapsed_seconds: int = Field(default=0, ge=0)
    consecutive_failures: int = Field(default=0, ge=0)
    proposed_actions: int = Field(default=0, ge=0)
    queued_actions: int = Field(default=0, ge=0)
    pending_approvals: int = Field(default=0, ge=0)
    unverified_results: int = Field(default=0, ge=0)


class AutonomyStepSummary(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    schema_version: Literal["v1"] = "v1"
    decision: str
    reason: str
    planner: Literal["bounded-planner-v2"] = "bounded-planner-v2"
    operator: Literal["policy-bound-operator-v2"] = "policy-bound-operator-v2"
    verifier: Literal["independent-verifier-v1"] = "independent-verifier-v1"
