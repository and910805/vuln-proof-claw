"""Versioned control-plane workflow API contracts."""

from __future__ import annotations

from datetime import datetime
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator

from vuln_proof_claw.domain.enums import ActionState, RiskLevel


class WorkflowSchema(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    schema_version: Literal["v1"] = "v1"


class FlowCreate(BaseModel):
    model_config = ConfigDict(extra="forbid")

    objective: str = Field(min_length=1, max_length=4000)

    @field_validator("objective")
    @classmethod
    def normalize_objective(cls, value: str) -> str:
        normalized = value.strip()
        if not normalized:
            raise ValueError("flow objective must not be empty")
        return normalized


class FlowSummary(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    id: str
    engagement_id: str
    objective: str
    created_at: datetime


class FlowListResponse(WorkflowSchema):
    items: tuple[FlowSummary, ...]
    total: int


class TaskCreate(BaseModel):
    model_config = ConfigDict(extra="forbid")

    title: str = Field(min_length=1, max_length=500)

    @field_validator("title")
    @classmethod
    def normalize_title(cls, value: str) -> str:
        normalized = value.strip()
        if not normalized:
            raise ValueError("task title must not be empty")
        return normalized


class TaskSummary(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    id: str
    flow_id: str
    title: str
    created_at: datetime


class TaskListResponse(WorkflowSchema):
    items: tuple[TaskSummary, ...]
    total: int


class HttpActionCreate(BaseModel):
    """Propose a bounded HTTP capture action; this does not execute it."""

    model_config = ConfigDict(extra="forbid")

    action_type: str = Field(min_length=1, max_length=255)
    method: Literal["GET", "HEAD"] = "GET"
    target: str = Field(min_length=1, max_length=2048)
    headers: dict[str, str] = Field(default_factory=dict)
    idempotency_key: str = Field(min_length=1, max_length=255)

    @field_validator("action_type", "idempotency_key")
    @classmethod
    def normalize_required_text(cls, value: str) -> str:
        normalized = value.strip()
        if not normalized:
            raise ValueError("value must not be empty")
        return normalized


class ActionSummary(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    id: str
    engagement_id: str
    task_id: str
    action_type: str
    normalized_target: str
    parameter_digest: str
    risk_level: RiskLevel
    idempotency_key: str
    state: ActionState
    approval_id: str | None
    policy_reason: str | None = None
    requires_dns_recheck: bool | None = None
    created_at: datetime


class ActionListResponse(WorkflowSchema):
    items: tuple[ActionSummary, ...]
    total: int


class AuditEventSummary(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    id: str
    engagement_id: str | None
    event_type: str
    actor: str
    payload: dict[str, Any]
    created_at: datetime


class AuditEventListResponse(WorkflowSchema):
    items: tuple[AuditEventSummary, ...]
    total: int
