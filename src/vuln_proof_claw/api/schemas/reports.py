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
    """One finding as a third party receives it.

    ``cwe_id`` and ``verification_method`` are what make the item auditable
    rather than merely readable: the first is the identifier an external
    consumer keys on, the second is the claim's stated basis. The domain
    refuses a HIGH or CRITICAL finding that never states a basis, so a report
    that omits it hides the very thing that rule exists to guarantee.
    """

    model_config = ConfigDict(extra="forbid", frozen=True)

    id: str
    title: str
    vulnerability_class: str
    cwe_id: str | None = None
    verification_method: str | None = None
    affected_target: str
    status: str
    severity: str
    confidence: str
    remediation: str
    evidence_ids: tuple[str, ...]
    version: int
    created_at: datetime


class DiscoverySummary(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    pages_scanned: int
    scanned_targets: tuple[str, ...]
    candidate_targets: tuple[str, ...]


class ApiOperationSummary(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    method: str
    path: str
    target: str
    operation_id: str | None
    requires_authentication: bool
    safe_to_probe: bool


class ApiInventorySummary(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    documents_found: int
    operations_total: int
    read_operations: int
    write_operations: int
    safe_probe_operations: int
    active_probes_run: int
    inventory_truncated: bool
    operations: tuple[ApiOperationSummary, ...]


class WorkflowStepItem(BaseModel):
    """One executed step: an action, its captured evidence, and its findings."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    index: int
    action_id: str
    action_type: str
    target: str
    state: str
    evidence_id: str | None
    evidence_digest: str | None
    finding_count: int
    finding_titles: tuple[str, ...]


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
    steps: tuple[WorkflowStepItem, ...] = ()
    evidence_integrity: EvidenceIntegrity
    discovery: DiscoverySummary
    api_inventory: ApiInventorySummary
    evidence: tuple[EvidenceReportItem, ...]
    findings: tuple[FindingReportItem, ...]
    raw_evidence_included: Literal[False] = False
    execution_available: bool = False


class ReportExportCreate(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    format: Literal["json", "markdown", "sarif"]


class ReportExportSummary(ReportSchema):
    id: str
    engagement_id: str
    format: Literal["json", "markdown", "sarif"]
    media_type: str
    digest: str
    size: int
    created_by: str
    created_at: datetime


class ReportExportList(ReportSchema):
    items: tuple[ReportExportSummary, ...]
    total: int
