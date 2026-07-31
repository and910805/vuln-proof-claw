"""Stable v1 schemas used by the Web console."""

from __future__ import annotations

from datetime import datetime
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator


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
