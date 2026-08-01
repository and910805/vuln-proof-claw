"""Metadata-only JSON and Markdown engagement reports."""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, status
from fastapi.responses import PlainTextResponse
from sqlalchemy import select
from sqlalchemy.orm import Session

from vuln_proof_claw.api.dependencies import get_session
from vuln_proof_claw.api.schemas.console import ScopeDefinition
from vuln_proof_claw.api.schemas.reports import (
    EngagementReport,
    EvidenceIntegrity,
    EvidenceReportItem,
    FindingReportItem,
    ReportCounts,
)
from vuln_proof_claw.domain.identifiers import EngagementId
from vuln_proof_claw.evidence.persistence import PersistentEvidenceStore
from vuln_proof_claw.persistence.models import (
    ActionRecord,
    EvidencePayloadRecord,
    EvidenceRecord,
    FindingRecord,
)
from vuln_proof_claw.persistence.repositories import EngagementRepository, ScopeRepository
from vuln_proof_claw.policy.scope import EngagementScope

router = APIRouter(tags=["reports"])
SessionDependency = Annotated[Session, Depends(get_session)]


def _scope_definition(scope: EngagementScope) -> ScopeDefinition:
    return ScopeDefinition(
        allowed_hostnames=tuple(sorted(scope.allowed_hostnames)),
        allowed_cidrs=tuple(str(item) for item in scope.allowed_networks),
        allowed_ports=tuple(sorted(scope.allowed_ports)),
        allowed_schemes=tuple(sorted(scope.allowed_schemes)),
        allowed_paths=scope.allowed_paths,
        denied_hostnames=tuple(sorted(scope.denied_hostnames)),
        denied_cidrs=tuple(str(item) for item in scope.denied_networks),
        denied_paths=scope.denied_paths,
        valid_from=scope.valid_from,
        valid_until=scope.valid_until,
    )


def build_engagement_report(session: Session, engagement_id: str) -> EngagementReport:
    normalized_id = EngagementId(engagement_id)
    stored = EngagementRepository(session).get(normalized_id)
    scope = ScopeRepository(session).get(normalized_id)
    if stored is None or scope is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="engagement_not_found")

    actions = tuple(
        session.scalars(
            select(ActionRecord)
            .where(ActionRecord.engagement_id == normalized_id)
            .order_by(ActionRecord.created_at, ActionRecord.id)
        )
    )
    evidence_rows = tuple(
        session.scalars(
            select(EvidenceRecord)
            .join(ActionRecord, EvidenceRecord.action_id == ActionRecord.id)
            .where(ActionRecord.engagement_id == normalized_id)
            .order_by(EvidenceRecord.captured_at, EvidenceRecord.id)
        )
    )
    finding_rows = tuple(
        session.scalars(
            select(FindingRecord)
            .where(FindingRecord.engagement_id == normalized_id)
            .order_by(FindingRecord.created_at, FindingRecord.id)
        )
    )
    action_states: dict[str, int] = {}
    for action in actions:
        action_states[action.state] = action_states.get(action.state, 0) + 1
    engagement = stored.entity
    payload_count = sum(
        1
        for _item in session.scalars(
            select(EvidencePayloadRecord.evidence_id).where(
                EvidencePayloadRecord.engagement_id == normalized_id
            )
        )
    )
    if payload_count != len(evidence_rows):
        integrity = EvidenceIntegrity(
            status="not_available",
            checked_records=payload_count,
            reason="raw_payload_unavailable",
        )
    else:
        verification = PersistentEvidenceStore(session).verify_engagement(normalized_id)
        integrity = EvidenceIntegrity(
            status="valid" if verification.valid else "invalid",
            checked_records=verification.checked_records,
            reason=verification.reason,
        )
    return EngagementReport(
        generated_at=datetime.now(UTC),
        engagement_id=engagement.id,
        project_id=engagement.project_id,
        engagement_name=engagement.name,
        starts_at=engagement.starts_at,
        ends_at=engagement.ends_at,
        scope=_scope_definition(scope),
        counts=ReportCounts(
            actions=len(actions),
            evidence=len(evidence_rows),
            findings=len(finding_rows),
        ),
        action_states=action_states,
        evidence_integrity=integrity,
        evidence=tuple(
            EvidenceReportItem(
                id=row.id,
                action_id=row.action_id,
                tool_name=row.tool_name,
                tool_version=row.tool_version,
                digest=row.digest,
                previous_digest=row.previous_digest,
                captured_at=row.captured_at,
            )
            for row in evidence_rows
        ),
        findings=tuple(
            FindingReportItem(
                id=row.id,
                title=row.title,
                vulnerability_class=row.vulnerability_class,
                affected_target=row.affected_target,
                status=row.status,
                created_at=row.created_at,
            )
            for row in finding_rows
        ),
    )


def _markdown_cell(value: object) -> str:
    return str(value).replace("|", "\\|").replace("\r", " ").replace("\n", " ")


def render_markdown(report: EngagementReport) -> str:
    lines = [
        f"# Engagement report: {_markdown_cell(report.engagement_name)}",
        "",
        f"- Report version: `{report.report_version}`",
        f"- Engagement ID: `{report.engagement_id}`",
        f"- Project ID: `{report.project_id}`",
        f"- Window: {report.starts_at.isoformat()} to {report.ends_at.isoformat()}",
        "- Raw evidence included: no",
        "- Target execution available: no",
        "",
        "## Authorized scope",
        "",
        f"- Hostnames: {', '.join(report.scope.allowed_hostnames) or 'none'}",
        f"- CIDRs: {', '.join(report.scope.allowed_cidrs) or 'none'}",
        f"- Ports: {', '.join(str(item) for item in report.scope.allowed_ports)}",
        f"- Schemes: {', '.join(report.scope.allowed_schemes)}",
        f"- Paths: {', '.join(report.scope.allowed_paths)}",
        "",
        "## Summary",
        "",
        f"- Actions: {report.counts.actions}",
        f"- Evidence records: {report.counts.evidence}",
        f"- Findings: {report.counts.findings}",
        f"- Evidence integrity: {report.evidence_integrity.status}",
        "",
        "## Findings",
        "",
    ]
    if report.findings:
        lines.extend(("| Status | Class | Title | Target |", "| --- | --- | --- | --- |"))
        lines.extend(
            "| " + " | ".join(
                _markdown_cell(value)
                for value in (
                    item.status,
                    item.vulnerability_class,
                    item.title,
                    item.affected_target,
                )
            ) + " |"
            for item in report.findings
        )
    else:
        lines.append("No findings have been recorded.")
    lines.extend(("", "## Evidence", ""))
    if report.evidence:
        lines.extend(("| Captured | Tool | Digest |", "| --- | --- | --- |"))
        lines.extend(
            f"| {item.captured_at.isoformat()} | {_markdown_cell(item.tool_name)} "
            f"| `{item.digest}` |"
            for item in report.evidence
        )
    else:
        lines.append("No evidence has been recorded.")
    return "\n".join(lines) + "\n"


@router.get(
    "/engagements/{engagement_id}/report",
    response_model=EngagementReport,
    summary="Generate a JSON engagement report",
)
def engagement_report(engagement_id: str, session: SessionDependency) -> EngagementReport:
    return build_engagement_report(session, engagement_id)


@router.get(
    "/engagements/{engagement_id}/report.md",
    response_class=PlainTextResponse,
    summary="Generate a Markdown engagement report",
)
def engagement_report_markdown(engagement_id: str, session: SessionDependency) -> str:
    return render_markdown(build_engagement_report(session, engagement_id))
