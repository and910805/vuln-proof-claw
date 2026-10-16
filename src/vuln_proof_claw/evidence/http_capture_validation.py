"""Rebuild a bounded HTTP observation from its persisted, authorized capture."""

from __future__ import annotations

import json
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any

from sqlalchemy.orm import Session

from vuln_proof_claw.domain.enums import ActionState, RiskLevel
from vuln_proof_claw.domain.errors import DomainValidationError
from vuln_proof_claw.domain.identifiers import EngagementId, EvidenceId
from vuln_proof_claw.evidence.persistence import PersistentEvidenceStore
from vuln_proof_claw.evidence.store import InvalidEvidenceError
from vuln_proof_claw.execution.http_capture import (
    HttpCaptureRequest,
    HttpCaptureResponse,
    InvalidHttpCaptureEvidenceError,
    capture_parameter_digest,
    parse_http_capture_evidence,
)
from vuln_proof_claw.persistence.models import (
    ActionRecord,
    ApprovalRecord,
    EvidencePayloadRecord,
)
from vuln_proof_claw.policy.risk import classify_risk

_CAPTURE_MEDIA_TYPE = "application/vnd.vuln-proof-claw.http-capture+json"
_CONTROLLED_CAPTURE_TOOLS = frozenset({"http-capture", "worker-http-capture"})


class PersistedCaptureValidationError(Exception):
    """A stored capture cannot support an automatic verification decision."""


@dataclass(frozen=True, slots=True)
class AuthorizedHttpCapture:
    """A response whose raw document and originating Action agree."""

    evidence_id: EvidenceId
    evidence_digest: str
    request: HttpCaptureRequest
    response: HttpCaptureResponse


def _utc(value: datetime) -> datetime:
    return value.replace(tzinfo=UTC) if value.tzinfo is None else value.astimezone(UTC)


def _canonical_metadata(session: Session, evidence_id: EvidenceId) -> dict[str, Any]:
    row = session.get(EvidencePayloadRecord, evidence_id)
    if row is None:
        raise PersistedCaptureValidationError("capture_payload_missing")
    try:
        value = json.loads(bytes(row.canonical_metadata))
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise PersistedCaptureValidationError("capture_metadata_invalid") from error
    if not isinstance(value, dict):
        raise PersistedCaptureValidationError("capture_metadata_invalid")
    return value


def _validate_approval(
    session: Session, action: ActionRecord, metadata: dict[str, Any]
) -> None:
    if metadata.get("approval_id") != action.approval_id:
        raise PersistedCaptureValidationError("capture_approval_mismatch")
    try:
        risk = RiskLevel(action.risk_level)
        if classify_risk(action.action_type) is not risk:
            raise PersistedCaptureValidationError("capture_risk_mismatch")
    except (DomainValidationError, ValueError) as error:
        raise PersistedCaptureValidationError("capture_risk_invalid") from error
    if risk.requires_approval and action.approval_id is None:
        raise PersistedCaptureValidationError("capture_approval_missing")
    if action.approval_id is None:
        return
    approval = session.get(ApprovalRecord, action.approval_id)
    if approval is None or action.started_at is None:
        raise PersistedCaptureValidationError("capture_approval_missing")
    if (
        approval.engagement_id != action.engagement_id
        or approval.action_type != action.action_type
        or approval.normalized_target != action.normalized_target
        or approval.parameter_digest != action.parameter_digest
        or approval.risk_level != action.risk_level
        or approval.consumed_executions < 1
        or not _utc(approval.approved_at)
        <= _utc(action.started_at)
        < _utc(approval.expires_at)
    ):
        raise PersistedCaptureValidationError("capture_approval_mismatch")


def load_authorized_http_capture(
    session: Session,
    engagement_id: EngagementId,
    evidence_id: EvidenceId,
    *,
    expected_target: str | None = None,
) -> AuthorizedHttpCapture:
    """Load one capture for a narrow automatic observation decision.

    The current database scope is not a historical scope snapshot. This verifies
    the recorded allowed decision and exact Action binding, not a fresh permission.
    """
    store = PersistentEvidenceStore(session)
    if not store.verify_engagement(engagement_id).valid:
        raise PersistedCaptureValidationError("capture_chain_invalid")
    try:
        stored = store.get_for_engagement(engagement_id, evidence_id)
    except (InvalidEvidenceError, DomainValidationError) as error:
        raise PersistedCaptureValidationError("capture_payload_invalid") from error
    if stored is None:
        raise PersistedCaptureValidationError("capture_payload_missing")
    if (
        stored.evidence.tool_name not in _CONTROLLED_CAPTURE_TOOLS
        or stored.media_type != _CAPTURE_MEDIA_TYPE
    ):
        raise PersistedCaptureValidationError("capture_source_untrusted")

    action = session.get(ActionRecord, stored.evidence.action_id)
    if action is None or action.engagement_id != engagement_id:
        raise PersistedCaptureValidationError("capture_action_mismatch")
    if (
        action.state != ActionState.SUCCEEDED.value
        or action.started_at is None
        or action.completed_at is None
        or not _utc(action.started_at)
        <= stored.evidence.captured_at
        <= _utc(action.completed_at)
    ):
        raise PersistedCaptureValidationError("capture_action_not_succeeded")

    try:
        parsed = parse_http_capture_evidence(
            stored.raw_content, action_id=stored.evidence.action_id
        )
    except (DomainValidationError, InvalidHttpCaptureEvidenceError) as error:
        raise PersistedCaptureValidationError("capture_document_invalid") from error
    request, response = parsed.request, parsed.response
    if (
        request.target != action.normalized_target
        or request.query != action.query
        or capture_parameter_digest(request) != action.parameter_digest
        or response.final_target != request.target
        or (expected_target is not None and request.target != expected_target)
    ):
        raise PersistedCaptureValidationError("capture_target_or_parameters_mismatch")

    metadata = _canonical_metadata(session, evidence_id)
    expected_parameters: dict[str, object] = {
        "headers": [list(item) for item in request.headers],
        "method": request.method,
        "target": request.target,
    }
    if request.query:
        expected_parameters["query"] = request.query
    expected_decision = "valid_approval" if action.approval_id else "automatic_policy_allow"
    if (
        metadata.get("normalized_parameters") != expected_parameters
        or metadata.get("scope_decision") != expected_decision
    ):
        raise PersistedCaptureValidationError("capture_metadata_mismatch")
    _validate_approval(session, action, metadata)
    return AuthorizedHttpCapture(evidence_id, stored.evidence.digest, request, response)
