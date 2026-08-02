"""Versioned, metadata-only engagement report contracts."""

from __future__ import annotations

from datetime import datetime
from typing import Literal

from pydantic import BaseModel, ConfigDict

from vuln_proof_claw.api.schemas.console import ScopeDefinition


class ReportSchema(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    schema_version: Literal["v1"] = "v1"


class EvidenceReportItem(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    id: str
    action_id: str
    tool_name: str
    tool_version: str
    digest: str
    previous_digest: str | None
    captured_at: datetime


class FindingReportItem(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    id: str
    title: str
    vulnerability_class: str
    affected_target: str
    status: str
    severity: str
    confidence: str
    remediation: str
    created_at: datetime


class DiscoverySummary(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    pages_scanned: int
    scanned_targets: tuple[str, ...]
    candidate_targets: tuple[str, ...]


class ReportCounts(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    actions: int
    evidence: int
    findings: int


class EvidenceIntegrity(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    status: Literal["valid", "invalid", "not_available"]
    checked_records: int
    reason: str | None = None


class EngagementReport(ReportSchema):
    report_version: Literal["v1"] = "v1"
    generated_at: datetime
    engagement_id: str
    project_id: str
    engagement_name: str
    starts_at: datetime
    ends_at: datetime
    scope: ScopeDefinition
    counts: ReportCounts
    action_states: dict[str, int]
    evidence_integrity: EvidenceIntegrity
    discovery: DiscoverySummary
    evidence: tuple[EvidenceReportItem, ...]
    findings: tuple[FindingReportItem, ...]
    raw_evidence_included: Literal[False] = False
    execution_available: Literal[False] = False


class ReportExportCreate(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    format: Literal["json", "markdown"]


class ReportExportSummary(ReportSchema):
    id: str
    engagement_id: str
    format: Literal["json", "markdown"]
    media_type: str
    digest: str
    size: int
    created_by: str
    created_at: datetime


class ReportExportList(ReportSchema):
    items: tuple[ReportExportSummary, ...]
    total: int
