"""Stable v1 schemas used by the Web console."""

from __future__ import annotations

from datetime import datetime
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from vuln_proof_claw.domain.enums import RiskLevel


class ConsoleSchema(BaseModel):
    """Strict base for Web console API contracts."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    schema_version: Literal["v1"] = "v1"


class ProjectCreate(BaseModel):
    """Create a top-level assessment project."""

    model_config = ConfigDict(extra="forbid")

    name: str = Field(min_length=1, max_length=255)

    @field_validator("name")
    @classmethod
    def normalize_name(cls, value: str) -> str:
        """Reject whitespace-only names and store a normalized value."""
        normalized = value.strip()
        if not normalized:
            raise ValueError("project name must not be empty")
        return normalized


class ProjectSummary(BaseModel):
    """Project data safe for list views."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    id: str
    name: str
    created_at: datetime


class ProjectListResponse(ConsoleSchema):
    """Paginated project collection."""

    items: tuple[ProjectSummary, ...]
    total: int


class ScopeDefinition(BaseModel):
    """Explicit allow/deny boundaries for one authorized engagement."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    allowed_hostnames: tuple[str, ...] = ()
    allowed_cidrs: tuple[str, ...] = ()
    allowed_ports: tuple[int, ...] = (443,)
    allowed_schemes: tuple[str, ...] = ("https",)
    allowed_paths: tuple[str, ...] = ("/",)
    denied_hostnames: tuple[str, ...] = ()
    denied_cidrs: tuple[str, ...] = ()
    denied_paths: tuple[str, ...] = ()
    valid_from: datetime | None = None
    valid_until: datetime | None = None

    @model_validator(mode="after")
    def require_allow_boundary(self) -> ScopeDefinition:
        if not self.allowed_hostnames and not self.allowed_cidrs:
            raise ValueError("scope requires at least one allowed hostname or CIDR")
        return self


class EngagementCreate(BaseModel):
    """Create a time-bounded engagement and its immutable initial scope."""

    model_config = ConfigDict(extra="forbid")

    name: str = Field(min_length=1, max_length=255)
    starts_at: datetime
    ends_at: datetime
    maximum_risk: RiskLevel = RiskLevel.L3
    destructive_actions_enabled: bool = False
    scope: ScopeDefinition

    @field_validator("name")
    @classmethod
    def normalize_name(cls, value: str) -> str:
        normalized = value.strip()
        if not normalized:
            raise ValueError("engagement name must not be empty")
        return normalized


class EngagementSummary(BaseModel):
    """Engagement data with its enforced normalized scope."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    id: str
    project_id: str
    name: str
    starts_at: datetime
    ends_at: datetime
    maximum_risk: RiskLevel
    destructive_actions_enabled: bool
    created_at: datetime
    scope: ScopeDefinition


class EngagementListResponse(ConsoleSchema):
    items: tuple[EngagementSummary, ...]
    total: int


class ScopeEvaluationRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    target: str = Field(min_length=1, max_length=2048)


class ScopeEvaluationResponse(ConsoleSchema):
    allowed: bool
    reason: str
    normalized_target: str
    requires_dns_recheck: bool


class DashboardCounts(BaseModel):
    """Control-plane entity counts."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    projects: int
    engagements: int
    active_actions: int
    pending_approvals: int
    evidence: int
    findings: int


class DashboardSummaryResponse(ConsoleSchema):
    """At-a-glance operational state for the Web console."""

    counts: DashboardCounts
    recent_projects: tuple[ProjectSummary, ...]
    execution_available: bool = False
    phase: Literal["web-foundation"] = "web-foundation"
