"""Approval and cancellation mutation contracts."""

from __future__ import annotations

from datetime import datetime
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, model_validator

from vuln_proof_claw.domain.enums import ActionState, RiskLevel


class ApprovalDecisionCreate(BaseModel):
    model_config = ConfigDict(extra="forbid")

    decision: Literal["approve", "deny"]
    reason: str | None = Field(default=None, max_length=1000)
    expires_in_seconds: int | None = Field(default=None, ge=60, le=3600)

    @model_validator(mode="after")
    def validate_decision_fields(self) -> ApprovalDecisionCreate:
        reason = self.reason.strip() if self.reason else None
        object.__setattr__(self, "reason", reason)
        if self.decision == "approve" and self.expires_in_seconds is None:
            object.__setattr__(self, "expires_in_seconds", 900)
        if self.decision == "deny" and self.expires_in_seconds is not None:
            raise ValueError("denial must not include an approval expiration")
        return self


class ActionCancelCreate(BaseModel):
    model_config = ConfigDict(extra="forbid")

    reason: str | None = Field(default=None, max_length=1000)


class ApprovalSummary(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    id: str
    engagement_id: str
    action_type: str
    normalized_target: str
    parameter_digest: str
    risk_level: RiskLevel
    expires_at: datetime
    permitted_executions: int
    consumed_executions: int
    approver: str
    approved_at: datetime


class ActionMutationResponse(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    schema_version: Literal["v1"] = "v1"
    action_id: str
    state: ActionState
    approval: ApprovalSummary | None = None


class ApprovalPresetCreate(BaseModel):
    model_config = ConfigDict(extra="forbid")

    name: str = Field(min_length=1, max_length=255)
    action_types: tuple[str, ...] = Field(min_length=1, max_length=16)
    target_prefixes: tuple[str, ...] = Field(min_length=1, max_length=16)
    maximum_risk: RiskLevel = RiskLevel.L1
    approval_ttl_seconds: int = Field(default=900, ge=60, le=3600)

    @model_validator(mode="after")
    def normalize_preset(self) -> ApprovalPresetCreate:
        name = self.name.strip()
        actions = tuple(
            sorted({item.strip().lower().replace(" ", "_") for item in self.action_types})
        )
        prefixes = tuple(sorted({item.strip() for item in self.target_prefixes}))
        if not name or any(not item for item in (*actions, *prefixes)):
            raise ValueError("preset values must not be blank")
        if any(not item.startswith(("http://", "https://")) for item in prefixes):
            raise ValueError("preset target prefixes must be absolute HTTP URLs")
        object.__setattr__(self, "name", name)
        object.__setattr__(self, "action_types", actions)
        object.__setattr__(self, "target_prefixes", prefixes)
        return self


class ApprovalPresetSummary(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    id: str
    engagement_id: str
    name: str
    action_types: tuple[str, ...]
    target_prefixes: tuple[str, ...]
    maximum_risk: RiskLevel
    approval_ttl_seconds: int
    enabled: bool
    created_by: str
    created_at: datetime


class ApprovalPresetList(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    items: tuple[ApprovalPresetSummary, ...]
    total: int


class ApprovalPresetApply(BaseModel):
    model_config = ConfigDict(extra="forbid")

    preset_id: str = Field(min_length=36, max_length=36)
