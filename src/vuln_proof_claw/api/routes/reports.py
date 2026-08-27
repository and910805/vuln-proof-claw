"""Metadata-only JSON, Markdown, and escaped HTML engagement reports."""

from __future__ import annotations

import base64
import hashlib
import html
import json
from datetime import UTC, datetime
from typing import Annotated

from fastapi import APIRouter, Depends, Header, HTTPException, Query, Response, status
from fastapi.responses import HTMLResponse, PlainTextResponse
from sqlalchemy import func, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from vuln_proof_claw import __version__
from vuln_proof_claw.api.audit import record_audit_event
from vuln_proof_claw.api.auth import (
    AuthenticatedPrincipal,
    require_evidence_reader,
    require_operator_if_configured,
)
from vuln_proof_claw.api.dependencies import get_session
from vuln_proof_claw.api.schemas.console import ScopeDefinition
from vuln_proof_claw.api.schemas.reports import (
    ApiInventorySummary,
    ApiOperationSummary,
    DiscoverySummary,
    EngagementReport,
    EvidenceIntegrity,
    EvidenceReportItem,
    FindingReportItem,
    ReportCounts,
    ReportExportCreate,
    ReportExportList,
    ReportExportSummary,
    WorkflowStepItem,
)
from vuln_proof_claw.assessment.discovery import discover_targets
from vuln_proof_claw.assessment.openapi import OpenApiDocument, parse_openapi_document
from vuln_proof_claw.domain.enums import ReportFormat
from vuln_proof_claw.domain.identifiers import EngagementId, EvidenceId, ReportExportId
from vuln_proof_claw.domain.models import ReportExport
from vuln_proof_claw.evidence.persistence import PersistentEvidenceStore
from vuln_proof_claw.evidence.store import InvalidEvidenceError
from vuln_proof_claw.execution.http_capture import HttpCaptureResponse
from vuln_proof_claw.persistence.models import (
    ActionRecord,
    EvidencePayloadRecord,
    EvidenceRecord,
    FindingRecord,
    ReportExportRecord,
    finding_evidence,
)
from vuln_proof_claw.persistence.repositories import (
    EngagementRepository,
    ReportExportRepository,
    ScopeRepository,
)
from vuln_proof_claw.policy.scope import EngagementScope
from vuln_proof_claw.reporting.bundle import build_disclosure_bundle

router = APIRouter(tags=["reports"])
SessionDependency = Annotated[Session, Depends(get_session)]
MAX_REPORT_EXPORT_BYTES = 10 * 1024 * 1024
OperatorDependency = Annotated[AuthenticatedPrincipal, Depends(require_operator_if_configured)]
EvidenceReaderDependency = Annotated[AuthenticatedPrincipal, Depends(require_evidence_reader)]


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
    finding_evidence_rows = tuple(
        session.execute(
            select(finding_evidence.c.finding_id, finding_evidence.c.evidence_id).where(
                finding_evidence.c.finding_id.in_(row.id for row in finding_rows)
            )
        )
    ) if finding_rows else ()
    evidence_ids_by_finding: dict[str, tuple[str, ...]] = {}
    for finding_id, evidence_id in finding_evidence_rows:
        evidence_ids_by_finding.setdefault(finding_id, ())
        evidence_ids_by_finding[finding_id] += (evidence_id,)
    action_states: dict[str, int] = {}
    for action in actions:
        action_states[action.state] = action_states.get(action.state, 0) + 1
    engagement = stored.entity
    assessment_actions = tuple(
        action
        for action in actions
        if action.action_type in {"passive_fingerprint", "passive_discovery"}
    )
    scanned_targets = tuple(
        dict.fromkeys(
            action.normalized_target
            for action in assessment_actions
            if action.state == "succeeded"
        )
    )
    candidates: dict[str, None] = {}
    api_documents: list[OpenApiDocument] = []
    evidence_store = PersistentEvidenceStore(session)
    for row in evidence_rows:
        try:
            stored_payload = evidence_store.get_for_engagement(normalized_id, EvidenceId(row.id))
        except InvalidEvidenceError:
            continue
        if stored_payload is None:
            continue
        try:
            capture = json.loads(stored_payload.raw_content)
            request_target = capture["request"]["target"]
            response_payload = capture["response"]
            response = HttpCaptureResponse(
                status_code=response_payload["status_code"],
                final_target=response_payload["final_target"],
                headers=tuple(tuple(item) for item in response_payload["headers"]),
                body=base64.b64decode(response_payload["body_base64"], validate=True),
                duration_ms=0,
            )
        except (KeyError, TypeError, ValueError, json.JSONDecodeError):
            continue
        for discovered in discover_targets(request_target, response):
            if discovered.url not in scanned_targets:
                candidates.setdefault(discovered.url, None)
        api_document = parse_openapi_document(request_target, response)
        if api_document is not None:
            api_documents.append(api_document)
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
    api_documents = list({item.source_url: item for item in api_documents}.values())
    unique_operations = {
        (operation.method, operation.target): operation
        for document in api_documents
        for operation in document.operations
    }
    operations = tuple(unique_operations.values())
    active_probes_run = sum(
        1
        for action in actions
        if action.action_type == "active_safe_api_read" and action.state == "succeeded"
    )
    steps = _build_steps(actions, evidence_rows, finding_rows, evidence_ids_by_finding)
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
        steps=tuple(steps),
        evidence_integrity=integrity,
        discovery=DiscoverySummary(
            pages_scanned=len(scanned_targets),
            scanned_targets=scanned_targets,
            candidate_targets=tuple(candidates),
        ),
        api_inventory=ApiInventorySummary(
            documents_found=len(api_documents),
            operations_total=len(operations),
            read_operations=sum(item.method in {"GET", "HEAD"} for item in operations),
            write_operations=sum(item.method not in {"GET", "HEAD"} for item in operations),
            safe_probe_operations=sum(item.safe_to_probe for item in operations),
            active_probes_run=active_probes_run,
            inventory_truncated=any(item.truncated for item in api_documents),
            operations=tuple(
                ApiOperationSummary(
                    method=item.method,
                    path=item.path,
                    target=item.target,
                    operation_id=item.operation_id,
                    requires_authentication=item.requires_authentication,
                    safe_to_probe=item.safe_to_probe,
                )
                for item in operations
            ),
        ),
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
                cwe_id=row.cwe_id,
                verification_method=row.verification_method,
                affected_target=row.affected_target,
                status=row.status,
                severity=row.severity,
                confidence=row.confidence,
                remediation=row.remediation,
                evidence_ids=evidence_ids_by_finding.get(row.id, ()),
                version=row.version,
                created_at=row.created_at,
            )
            for row in finding_rows
        ),
        execution_available=active_probes_run > 0,
    )


def _build_steps(
    actions: tuple[ActionRecord, ...],
    evidence_rows: tuple[EvidenceRecord, ...],
    finding_rows: tuple[FindingRecord, ...],
    evidence_ids_by_finding: dict[str, tuple[str, ...]],
) -> tuple[WorkflowStepItem, ...]:
    """Correlate each action with its captured evidence and evidence-linked findings."""
    evidence_by_action: dict[str, EvidenceRecord] = {}
    for row in evidence_rows:
        evidence_by_action.setdefault(row.action_id, row)
    action_by_evidence = {row.id: row.action_id for row in evidence_rows}
    findings_by_action: dict[str, list[FindingRecord]] = {}
    for finding in finding_rows:
        for evidence_id in evidence_ids_by_finding.get(finding.id, ()):
            owning_action = action_by_evidence.get(evidence_id)
            if owning_action is not None:
                findings_by_action.setdefault(owning_action, []).append(finding)
    steps: list[WorkflowStepItem] = []
    for index, action in enumerate(actions, start=1):
        captured = evidence_by_action.get(action.id)
        step_findings = findings_by_action.get(action.id, [])
        steps.append(
            WorkflowStepItem(
                index=index,
                action_id=action.id,
                action_type=action.action_type,
                target=action.normalized_target,
                state=action.state,
                evidence_id=captured.id if captured else None,
                evidence_digest=captured.digest if captured else None,
                finding_count=len(step_findings),
                finding_titles=tuple(dict.fromkeys(finding.title for finding in step_findings)),
            )
        )
    return tuple(steps)


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
        f"- Safe active execution used: {'yes' if report.execution_available else 'no'}",
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
        f"- Pages scanned: {report.discovery.pages_scanned}",
        f"- OpenAPI documents: {report.api_inventory.documents_found}",
        f"- API operations: {report.api_inventory.operations_total}",
        f"- Safe active API probes: {report.api_inventory.active_probes_run}",
        f"- Evidence integrity: {report.evidence_integrity.status}",
        "",
        "## Execution steps",
        "",
    ]
    if report.steps:
        lines.extend(
            (
                "| Step | Target | Action | State | Evidence digest | Findings |",
                "| --- | --- | --- | --- | --- | --- |",
            )
        )
        lines.extend(
            "| "
            + " | ".join(
                _markdown_cell(value)
                for value in (
                    step.index,
                    step.target,
                    step.action_type,
                    step.state,
                    step.evidence_digest or "—",
                    f"{step.finding_count}: {'; '.join(step.finding_titles)}"
                    if step.finding_count
                    else "0",
                )
            )
            + " |"
            for step in report.steps
        )
    else:
        lines.append("No execution steps have been recorded.")
    lines.extend(("", "## Findings", ""))
    if report.findings:
        lines.extend(
            (
                "| Severity | Confidence | Class | Title | Target | Remediation |",
                "| --- | --- | --- | --- | --- | --- |",
            )
        )
        lines.extend(
            "| "
            + " | ".join(
                _markdown_cell(value)
                for value in (
                    item.severity,
                    item.confidence,
                    item.vulnerability_class,
                    item.title,
                    item.affected_target,
                    item.remediation,
                )
            )
            + " |"
            for item in report.findings
        )
    else:
        lines.append("No findings have been recorded.")
    lines.extend(("", "## API operation inventory", ""))
    if report.api_inventory.operations:
        lines.extend(
            (
                "| Method | Path | Authentication | Safe probe |",
                "| --- | --- | --- | --- |",
            )
        )
        lines.extend(
            f"| {item.method} | {_markdown_cell(item.path)} | "
            f"{'required' if item.requires_authentication else 'not declared'} | "
            f"{'yes' if item.safe_to_probe else 'no'} |"
            for item in report.api_inventory.operations
        )
    else:
        lines.append("No OpenAPI operations were discovered.")
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


def render_html(report: EngagementReport) -> str:
    """Render a standalone, escaped HTML preview without active content."""
    escape = html.escape
    finding_rows = "".join(
        "<tr>"
        f'<td><span class="severity {escape(item.severity)}">{escape(item.severity)}</span></td>'
        f"<td>{escape(item.confidence)}</td><td>{escape(item.vulnerability_class)}</td>"
        f"<td><strong>{escape(item.title)}</strong><br><small>{escape(item.affected_target)}</small></td>"
        f"<td>{escape(item.remediation)}</td></tr>"
        for item in report.findings
    ) or '<tr><td colspan="5">No findings recorded.</td></tr>'
    target_rows = "".join(
        f"<li><code>{escape(item)}</code></li>" for item in report.discovery.scanned_targets
    )
    step_rows = "".join(
        "<tr>"
        f"<td>{step.index}</td><td><code>{escape(step.target)}</code></td>"
        f"<td>{escape(step.action_type)}</td><td>{escape(step.state)}</td>"
        f"<td><code>{escape(step.evidence_digest or '—')}</code></td>"
        f"<td>{step.finding_count}"
        + (
            f"<br><small>{escape('; '.join(step.finding_titles))}</small>"
            if step.finding_titles
            else ""
        )
        + "</td></tr>"
        for step in report.steps
    ) or '<tr><td colspan="6">No execution steps recorded.</td></tr>'
    operation_rows = "".join(
        "<tr>"
        f"<td><strong>{escape(item.method)}</strong></td><td><code>{escape(item.path)}</code></td>"
        f"<td>{'required' if item.requires_authentication else 'not declared'}</td>"
        f"<td>{'yes' if item.safe_to_probe else 'no'}</td></tr>"
        for item in report.api_inventory.operations
    ) or '<tr><td colspan="4">No OpenAPI operations discovered.</td></tr>'
    return f"""<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width">
<title>ProofClaw report — {escape(report.engagement_name)}</title>
<style>
:root {{ color-scheme: dark; font-family: Inter, system-ui, sans-serif;
background:#07100f; color:#eef5ef; }}
body {{ margin:0; padding:40px 24px; }} main {{ max-width:1100px; margin:auto; }}
h1 {{ font-size:clamp(2rem,5vw,4rem); margin:.2em 0; }}
.kicker {{ color:#b9ff37; letter-spacing:.12em; }}
.grid {{ display:grid; grid-template-columns:repeat(auto-fit,minmax(180px,1fr));
gap:12px; margin:28px 0; }}
.card {{ background:#111b1a; border:1px solid #293937; border-radius:12px; padding:18px; }}
.value {{ font-size:2rem; font-weight:700; }} table {{ width:100%; border-collapse:collapse; }}
th,td {{ padding:12px; text-align:left; vertical-align:top; border-bottom:1px solid #293937; }}
small,code {{ color:#a9bab7; }} .severity {{ text-transform:uppercase; font-weight:700; }}
.high,.critical {{ color:#ff776f; }} .medium {{ color:#ffc75f; }} .low {{ color:#77d9ff; }}
@media(max-width:700px) {{ body {{ padding:24px 12px; }}
table {{ display:block; overflow:auto; }} }}
</style></head><body><main>
<p class="kicker">PROOFCLAW EVIDENCE REPORT</p><h1>{escape(report.engagement_name)}</h1>
<p>Generated {escape(report.generated_at.isoformat())} · Evidence integrity:
<strong>{escape(report.evidence_integrity.status)}</strong></p>
<section class="grid"><div class="card">
<div class="value">{report.discovery.pages_scanned}</div>Pages scanned</div>
<div class="card"><div class="value">{report.counts.findings}</div>Findings</div>
<div class="card"><div class="value">{report.counts.evidence}</div>Evidence records</div></section>
<section class="grid"><div class="card"><div class="value">
{report.api_inventory.operations_total}</div>API operations</div>
<div class="card"><div class="value">
{report.api_inventory.active_probes_run}</div>Safe active probes</div></section>
<h2>Execution steps</h2><div class="card"><table><thead><tr><th>#</th><th>Target</th>
<th>Action</th><th>State</th><th>Evidence digest</th><th>Findings</th></tr></thead>
<tbody>{step_rows}</tbody></table></div>
<h2>Findings</h2><div class="card"><table><thead><tr><th>Severity</th>
<th>Confidence</th><th>Class</th><th>Finding</th><th>Remediation</th></tr></thead>
<tbody>{finding_rows}</tbody></table></div>
<h2>API operation inventory</h2><div class="card"><table><thead><tr><th>Method</th>
<th>Path</th><th>Authentication</th><th>Safe probe</th></tr></thead>
<tbody>{operation_rows}</tbody></table></div>
<h2>Scanned targets</h2><div class="card"><ul>{target_rows}</ul></div>
    </main></body></html>"""


def render_sarif(report: EngagementReport) -> bytes:
    """Render a SARIF 2.1.0 result set without raw target evidence."""
    levels = {
        "critical": "error",
        "high": "error",
        "medium": "warning",
        "low": "note",
        "informational": "note",
    }
    rules: dict[str, dict[str, object]] = {}
    results: list[dict[str, object]] = []
    for finding in report.findings:
        rules.setdefault(
            finding.vulnerability_class,
            {
                "id": finding.vulnerability_class,
                "name": finding.vulnerability_class,
                "shortDescription": {"text": finding.title},
                "help": {"text": finding.remediation},
            },
        )
        result: dict[str, object] = {
            "ruleId": finding.vulnerability_class,
            "level": levels.get(finding.severity, "warning"),
            "message": {"text": finding.title},
            "locations": [
                {"physicalLocation": {"artifactLocation": {"uri": finding.affected_target}}}
            ],
            "properties": {
                "proofclaw_status": finding.status,
                "proofclaw_confidence": finding.confidence,
                "proofclaw_finding_id": finding.id,
                "proofclaw_evidence_ids": list(finding.evidence_ids),
                "proofclaw_remediation": finding.remediation,
                "proofclaw_version": finding.version,
            },
        }
        if finding.status == "rejected":
            result["suppressions"] = [
                {"kind": "inSource", "justification": "Rejected during review"}
            ]
        results.append(result)
    payload = {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "vuln-proof-claw",
                        "semanticVersion": __version__,
                        "informationUri": "https://github.com/and910805/vuln-proof-claw",
                        "rules": list(rules.values()),
                    }
                },
                "automationDetails": {"id": report.engagement_id},
                "properties": {
                    "proofclaw_report_version": report.report_version,
                    "proofclaw_engagement_id": report.engagement_id,
                    "proofclaw_evidence_integrity": report.evidence_integrity.status,
                },
                "results": results,
            }
        ],
    }
    return (json.dumps(payload, ensure_ascii=False, indent=2, sort_keys=True) + "\n").encode()


def _export_summary(export: ReportExport) -> ReportExportSummary:
    return ReportExportSummary(
        id=export.id,
        engagement_id=export.engagement_id,
        format=export.format.value,
        media_type=export.media_type,
        digest=export.digest,
        size=export.size,
        created_by=export.created_by,
        created_at=export.created_at,
    )


def _serialize_report(report: EngagementReport, export_format: ReportFormat) -> tuple[str, bytes]:
    if export_format is ReportFormat.JSON:
        return "application/json", (report.model_dump_json(indent=2) + "\n").encode()
    if export_format is ReportFormat.SARIF:
        return "application/sarif+json", render_sarif(report)
    return "text/markdown", render_markdown(report).encode()


def _download_response(content: bytes, *, media_type: str, filename: str, digest: str) -> Response:
    return Response(
        content=content,
        media_type=media_type,
        headers={
            "Cache-Control": "no-store",
            "Content-Disposition": f'attachment; filename="{filename}"',
            "ETag": f'"sha256:{digest}"',
            "X-Content-SHA256": digest,
            "X-Content-Type-Options": "nosniff",
        },
    )


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


@router.get(
    "/engagements/{engagement_id}/report.html",
    response_class=HTMLResponse,
    summary="Preview an escaped HTML engagement report",
)
def engagement_report_html(engagement_id: str, session: SessionDependency) -> HTMLResponse:
    content = render_html(build_engagement_report(session, engagement_id))
    return HTMLResponse(
        content,
        headers={
            "Cache-Control": "no-store",
            "Content-Security-Policy": "default-src 'none'; style-src 'unsafe-inline'",
            "X-Content-Type-Options": "nosniff",
        },
    )


@router.get(
    "/engagements/{engagement_id}/report.sarif",
    summary="Generate a SARIF 2.1.0 engagement report",
)
def engagement_report_sarif(engagement_id: str, session: SessionDependency) -> Response:
    return Response(
        content=render_sarif(build_engagement_report(session, engagement_id)),
        media_type="application/sarif+json",
        headers={
            "Cache-Control": "no-store",
            "Content-Disposition": "inline; filename=engagement.sarif",
        },
    )


@router.get(
    "/engagements/{engagement_id}/report.bundle.zip",
    summary="Download a self-verifiable metadata-only disclosure bundle",
)
def engagement_report_bundle(engagement_id: str, session: SessionDependency) -> Response:
    report = build_engagement_report(session, engagement_id)
    try:
        content = build_disclosure_bundle(
            report,
            markdown=render_markdown(report).encode(),
            html=render_html(report).encode(),
            sarif=render_sarif(report),
        )
    except ValueError as error:
        raise HTTPException(status_code=413, detail="report_bundle_too_large") from error
    return _download_response(
        content,
        media_type="application/zip",
        filename=f"engagement-{engagement_id}-disclosure.zip",
        digest=hashlib.sha256(content).hexdigest(),
    )


@router.post(
    "/engagements/{engagement_id}/report-exports",
    response_model=ReportExportSummary,
    status_code=status.HTTP_201_CREATED,
    summary="Create an immutable engagement report export",
)
def create_report_export(  # noqa: PLR0913, PLR0917 - explicit HTTP dependencies
    engagement_id: str,
    payload: ReportExportCreate,
    session: SessionDependency,
    principal: OperatorDependency,
    response: Response,
    idempotency_key: Annotated[str, Header(alias="Idempotency-Key", min_length=1, max_length=255)],
) -> ReportExportSummary:
    normalized_id = EngagementId(engagement_id)
    repository = ReportExportRepository(session)
    existing = repository.get_by_idempotency_key(normalized_id, idempotency_key)
    requested_format = ReportFormat(payload.format)
    if existing is not None:
        if existing.entity.format is not requested_format:
            raise HTTPException(status_code=409, detail="idempotency_key_conflict")
        response.status_code = status.HTTP_200_OK
        return _export_summary(existing.entity)

    report = build_engagement_report(session, engagement_id)
    media_type, content = _serialize_report(report, requested_format)
    if len(content) > MAX_REPORT_EXPORT_BYTES:
        raise HTTPException(status_code=413, detail="report_export_too_large")
    digest = hashlib.sha256(content).hexdigest()
    export = ReportExport(
        engagement_id=normalized_id,
        format=requested_format,
        media_type=media_type,
        digest=digest,
        size=len(content),
        idempotency_key=idempotency_key,
        created_by=principal.identity,
    )
    try:
        repository.add(export, content)
        record_audit_event(
            session,
            normalized_id,
            "report.export_created",
            principal.identity,
            {"report_export_id": export.id, "format": export.format.value, "digest": digest},
        )
        session.commit()
    except IntegrityError:
        session.rollback()
        replay = repository.get_by_idempotency_key(normalized_id, idempotency_key)
        if replay is None:
            raise
        if replay.entity.format is not requested_format:
            raise HTTPException(status_code=409, detail="idempotency_key_conflict") from None
        response.status_code = status.HTTP_200_OK
        return _export_summary(replay.entity)
    return _export_summary(export)


@router.get(
    "/engagements/{engagement_id}/report-exports",
    response_model=ReportExportList,
    summary="List immutable report exports without their content",
)
def list_report_exports(
    engagement_id: str,
    session: SessionDependency,
    limit: Annotated[int, Query(ge=1, le=100)] = 50,
    offset: Annotated[int, Query(ge=0)] = 0,
) -> ReportExportList:
    normalized_id = EngagementId(engagement_id)
    if EngagementRepository(session).get(normalized_id) is None:
        raise HTTPException(status_code=404, detail="engagement_not_found")
    repository = ReportExportRepository(session)
    return ReportExportList(
        items=tuple(
            _export_summary(item)
            for item in repository.list_for_engagement(normalized_id, limit=limit, offset=offset)
        ),
        total=session.scalar(
            select(func.count())
            .select_from(ReportExportRecord)
            .where(ReportExportRecord.engagement_id == normalized_id)
        )
        or 0,
    )


@router.get(
    "/engagements/{engagement_id}/report-exports/{export_id}/download",
    summary="Download and verify an immutable report export",
)
def download_report_export(
    engagement_id: str,
    export_id: str,
    session: SessionDependency,
    principal: EvidenceReaderDependency,
) -> Response:
    normalized_id = EngagementId(engagement_id)
    stored = ReportExportRepository(session).get(ReportExportId(export_id))
    if stored is None or stored.entity.engagement_id != normalized_id:
        raise HTTPException(status_code=404, detail="report_export_not_found")
    actual_digest = hashlib.sha256(stored.content).hexdigest()
    if len(stored.content) != stored.entity.size or actual_digest != stored.entity.digest:
        raise HTTPException(status_code=409, detail="report_export_integrity_failed")
    record_audit_event(
        session,
        normalized_id,
        "report.export_downloaded",
        principal.identity,
        {"report_export_id": stored.entity.id, "digest": stored.entity.digest},
    )
    session.commit()
    extension = {
        ReportFormat.JSON: "json",
        ReportFormat.MARKDOWN: "md",
        ReportFormat.SARIF: "sarif",
    }[stored.entity.format]
    return _download_response(
        stored.content,
        media_type=stored.entity.media_type,
        filename=f"engagement-{engagement_id}-{export_id}.{extension}",
        digest=stored.entity.digest,
    )


@router.get(
    "/engagements/{engagement_id}/evidence/{evidence_id}/raw",
    summary="Download integrity-checked raw evidence with an audit record",
)
def download_raw_evidence(
    engagement_id: str,
    evidence_id: str,
    session: SessionDependency,
    principal: EvidenceReaderDependency,
) -> Response:
    normalized_id = EngagementId(engagement_id)
    store = PersistentEvidenceStore(session)
    verification = store.verify_engagement(normalized_id)
    if not verification.valid:
        raise HTTPException(status_code=409, detail="evidence_integrity_failed")
    try:
        stored = store.get_for_engagement(normalized_id, EvidenceId(evidence_id))
    except InvalidEvidenceError:
        raise HTTPException(status_code=409, detail="evidence_integrity_failed") from None
    if stored is None:
        raise HTTPException(status_code=404, detail="evidence_not_found")
    record_audit_event(
        session,
        normalized_id,
        "evidence.raw_accessed",
        principal.identity,
        {"evidence_id": evidence_id, "digest": stored.evidence.digest},
    )
    session.commit()
    response = _download_response(
        stored.raw_content,
        media_type=stored.media_type,
        filename=f"evidence-{evidence_id}.bin",
        digest=hashlib.sha256(stored.raw_content).hexdigest(),
    )
    response.headers["X-Evidence-Digest"] = stored.evidence.digest
    return response
