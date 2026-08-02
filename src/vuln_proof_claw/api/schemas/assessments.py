"""Stable passive URL assessment API contracts."""

from __future__ import annotations

from datetime import datetime
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field

from vuln_proof_claw.domain.enums import ActionState


class AssessmentCreate(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    target: str = Field(min_length=1, max_length=2048)
    preset: Literal["safe", "fast", "deep"] = "safe"


class AssessmentSummary(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    schema_version: Literal["v1"] = "v1"
    action_id: str
    engagement_id: str
    state: ActionState
    evidence_ids: tuple[str, ...]
    finding_ids: tuple[str, ...]
    findings_count: int
    error_code: str | None
    replayed: bool
    pages_scanned: int
    crawl_truncated: bool
    report_url: str
    markdown_report_url: str
    html_report_url: str


class AssessmentHistoryItem(BaseModel):
    """Persisted assessment metadata safe for operational list views."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    action_id: str
    engagement_id: str
    project_id: str
    target: str
    state: ActionState
    created_at: datetime
    completed_at: datetime | None
    evidence_count: int
    findings_count: int
    error_code: str | None
    report_url: str
    markdown_report_url: str


class AssessmentListResponse(BaseModel):
    """Paginated passive-assessment history."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    schema_version: Literal["v1"] = "v1"
    items: tuple[AssessmentHistoryItem, ...]
    total: int
