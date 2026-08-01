"""Stable passive URL assessment API contracts."""

from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, ConfigDict, Field

from vuln_proof_claw.domain.enums import ActionState


class AssessmentCreate(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    target: str = Field(min_length=1, max_length=2048)


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
    report_url: str
    markdown_report_url: str
