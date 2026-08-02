"""Finding review API contracts."""

from __future__ import annotations

from datetime import datetime
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator

FindingReviewStatus = Literal[
    "pending_verification",
    "verified",
    "rejected",
    "needs_manual_review",
]


class FindingReviewRequest(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    status: FindingReviewStatus
    expected_version: int = Field(ge=1)
    comment: str | None = Field(default=None, max_length=4000)

    @field_validator("comment")
    @classmethod
    def normalize_comment(cls, value: str | None) -> str | None:
        if value is None:
            return None
        normalized = value.strip()
        return normalized or None


class FindingReviewSummary(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    schema_version: Literal["v1"] = "v1"
    id: str
    engagement_id: str
    title: str
    vulnerability_class: str
    affected_target: str
    status: str
    severity: str
    confidence: str
    remediation: str
    evidence_ids: tuple[str, ...]
    version: int
    reviewed_at: datetime
    reviewed_by: str
