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
