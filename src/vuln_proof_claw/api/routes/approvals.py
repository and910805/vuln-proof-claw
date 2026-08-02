"""Authenticated approval decisions and operator cancellation."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from typing import Annotated
from urllib.parse import urlsplit

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from vuln_proof_claw.api.audit import record_audit_event
from vuln_proof_claw.api.auth import (
    AuthenticatedPrincipal,
    require_approver,
    require_operator_if_configured,
)
from vuln_proof_claw.api.dependencies import get_session
from vuln_proof_claw.api.schemas.approvals import (
    ActionCancelCreate,
    ActionMutationResponse,
    ApprovalDecisionCreate,
    ApprovalPresetApply,
    ApprovalPresetCreate,
    ApprovalPresetList,
    ApprovalPresetSummary,
    ApprovalSummary,
)
from vuln_proof_claw.domain.action_state import TERMINAL_ACTION_STATES, transition_action
from vuln_proof_claw.domain.enums import ActionState, RiskLevel
from vuln_proof_claw.domain.identifiers import ActionId, EngagementId, new_identifier
from vuln_proof_claw.domain.models import Action, Approval
from vuln_proof_claw.persistence.models import ApprovalPresetRecord
from vuln_proof_claw.persistence.repositories import (
    ActionRepository,
    ApprovalRepository,
    ConcurrentUpdateError,
    EngagementRepository,
    ScopeRepository,
    Stored,
)
from vuln_proof_claw.policy.decision import DecisionKind, PolicyConfig, decide_action

router = APIRouter(tags=["approvals"])
SessionDependency = Annotated[Session, Depends(get_session)]
ApproverDependency = Annotated[AuthenticatedPrincipal, Depends(require_approver)]
OperatorDependency = Annotated[
    AuthenticatedPrincipal,
    Depends(require_operator_if_configured),
]


def _approval_summary(approval: Approval) -> ApprovalSummary:
    return ApprovalSummary(
        id=approval.id,
        engagement_id=approval.engagement_id,
        action_type=approval.action_type,
        normalized_target=approval.normalized_target,
        parameter_digest=approval.parameter_digest,
        risk_level=approval.risk_level,
        expires_at=approval.expires_at,
        permitted_executions=approval.permitted_executions,
        consumed_executions=approval.consumed_executions,
        approver=approval.approver,
        approved_at=approval.approved_at,
    )


def _preset_summary(row: ApprovalPresetRecord) -> ApprovalPresetSummary:
    return ApprovalPresetSummary(
        id=row.id,
        engagement_id=row.engagement_id,
        name=row.name,
        action_types=tuple(row.action_types),
        target_prefixes=tuple(row.target_prefixes),
        maximum_risk=RiskLevel(row.maximum_risk),
        approval_ttl_seconds=row.approval_ttl_seconds,
        enabled=row.enabled,
        created_by=row.created_by,
        created_at=row.created_at,
    )


def _target_matches_prefix(target: str, prefix: str) -> bool:
    target_url = urlsplit(target)
    prefix_url = urlsplit(prefix)
    target_port = target_url.port or (443 if target_url.scheme == "https" else 80)
    prefix_port = prefix_url.port or (443 if prefix_url.scheme == "https" else 80)
    prefix_path = prefix_url.path.rstrip("/") or "/"
    path_matches = prefix_path in {"/", target_url.path} or target_url.path.startswith(
        f"{prefix_path}/"
    )
    return (
        target_url.scheme == prefix_url.scheme
        and target_url.hostname == prefix_url.hostname
        and target_port == prefix_port
        and path_matches
    )


@router.post(
    "/engagements/{engagement_id}/approval-presets",
    response_model=ApprovalPresetSummary,
    status_code=status.HTTP_201_CREATED,
    summary="Create a reusable approval preset",
)
def create_approval_preset(
    engagement_id: str,
    payload: ApprovalPresetCreate,
    session: SessionDependency,
    principal: ApproverDependency,
) -> ApprovalPresetSummary:
    normalized_id = EngagementId(engagement_id)
    engagement = EngagementRepository(session).get(normalized_id)
    if engagement is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="engagement_not_found")
    if int(payload.maximum_risk.value[1]) > int(engagement.entity.maximum_risk.value[1]):
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_CONTENT,
            detail="preset_exceeds_engagement_risk",
        )
    timestamp = datetime.now(UTC)
    row = ApprovalPresetRecord(
        id=new_identifier(),
        engagement_id=engagement_id,
        name=payload.name,
        action_types=list(payload.action_types),
        target_prefixes=list(payload.target_prefixes),
        maximum_risk=payload.maximum_risk.value,
        approval_ttl_seconds=payload.approval_ttl_seconds,
        enabled=True,
        created_by=principal.identity,
        created_at=timestamp,
    )
    session.add(row)
    try:
        session.flush()
    except IntegrityError as error:
        session.rollback()
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="approval_preset_name_conflict",
        ) from error
    record_audit_event(
        session,
        normalized_id,
        "approval_preset.created",
        principal.identity,
        {
            "preset_id": row.id,
            "action_types": row.action_types,
            "target_prefixes": row.target_prefixes,
            "maximum_risk": row.maximum_risk,
        },
        at=timestamp,
    )
    session.commit()
    return _preset_summary(row)


@router.get(
    "/engagements/{engagement_id}/approval-presets",
    response_model=ApprovalPresetList,
    summary="List reusable approval presets",
)
def list_approval_presets(
    engagement_id: str,
    session: SessionDependency,
) -> ApprovalPresetList:
    if EngagementRepository(session).get(EngagementId(engagement_id)) is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="engagement_not_found")
    rows = tuple(
        session.scalars(
            select(ApprovalPresetRecord)
            .where(ApprovalPresetRecord.engagement_id == engagement_id)
            .order_by(ApprovalPresetRecord.created_at.desc())
        )
    )
    return ApprovalPresetList(items=tuple(_preset_summary(row) for row in rows), total=len(rows))


@router.post(
    "/actions/{action_id}/apply-approval-preset",
    response_model=ActionMutationResponse,
    summary="Apply a pre-approved preset to one exact pending Action",
)
def apply_approval_preset(
    action_id: str,
    payload: ApprovalPresetApply,
    session: SessionDependency,
    principal: OperatorDependency,
) -> ActionMutationResponse:
    repository = ActionRepository(session)
    stored_action = repository.get(ActionId(action_id))
    if stored_action is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="action_not_found")
    action = stored_action.entity
    if action.state is not ActionState.PENDING_APPROVAL:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT, detail="action_not_pending_approval"
        )
    preset = session.get(ApprovalPresetRecord, payload.preset_id)
    if preset is None or preset.engagement_id != action.engagement_id:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, detail="approval_preset_not_found"
        )
    if not preset.enabled:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="approval_preset_disabled")
    if action.action_type not in preset.action_types:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT, detail="preset_action_type_mismatch"
        )
    if not any(
        _target_matches_prefix(action.normalized_target, prefix)
        for prefix in preset.target_prefixes
    ):
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="preset_target_mismatch")
    if int(action.risk_level.value[1]) > int(preset.maximum_risk[1]):
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="preset_risk_exceeded")

    timestamp = datetime.now(UTC)
    engagement = EngagementRepository(session).get(action.engagement_id)
    if engagement is None:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="engagement_missing")
    expires_at = min(
        timestamp + timedelta(seconds=preset.approval_ttl_seconds),
        engagement.entity.ends_at,
    )
    approval = Approval(
        engagement_id=action.engagement_id,
        action_type=action.action_type,
        normalized_target=action.normalized_target,
        parameter_digest=action.parameter_digest,
        risk_level=action.risk_level,
        expires_at=expires_at,
        permitted_executions=1,
        approver=preset.created_by,
        approved_at=timestamp,
    )
    ApprovalRepository(session).add(approval)
    queued = transition_action(action, ActionState.QUEUED, approval=approval, at=timestamp)
    saved = _save_action(repository, queued, expected_version=stored_action.version)
    record_audit_event(
        session,
        action.engagement_id,
        "approval_preset.applied",
        principal.identity,
        {"preset_id": preset.id, "action_id": action.id, "approval_id": approval.id},
        at=timestamp,
    )
    session.commit()
    return ActionMutationResponse(
        action_id=action.id,
        state=saved.entity.state,
        approval=_approval_summary(approval),
    )


def _save_action(
    repository: ActionRepository,
    action: Action,
    *,
    expected_version: int,
) -> Stored[Action]:
    try:
        return repository.save(action, expected_version=expected_version)
    except ConcurrentUpdateError as error:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="action_concurrently_modified",
        ) from error


@router.post(
    "/actions/{action_id}/approval-decision",
    response_model=ActionMutationResponse,
    summary="Approve or deny one pending Action",
)
def decide_pending_action(
    action_id: str,
    payload: ApprovalDecisionCreate,
    session: SessionDependency,
    principal: ApproverDependency,
) -> ActionMutationResponse:
    repository = ActionRepository(session)
    stored_action = repository.get(ActionId(action_id))
    if stored_action is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="action_not_found")
    action = stored_action.entity
    if action.state is not ActionState.PENDING_APPROVAL:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="action_not_pending_approval",
        )
    timestamp = datetime.now(UTC)

    if payload.decision == "deny":
        denied = transition_action(action, ActionState.DENIED, at=timestamp)
        saved = _save_action(repository, denied, expected_version=stored_action.version)
        record_audit_event(
            session,
            action.engagement_id,
            "approval.denied",
            principal.identity,
            {"action_id": action.id, "reason": payload.reason},
            at=timestamp,
        )
        session.commit()
        return ActionMutationResponse(action_id=action.id, state=saved.entity.state)

    stored_engagement = EngagementRepository(session).get(action.engagement_id)
    scope = ScopeRepository(session).get(action.engagement_id)
    if stored_engagement is None or scope is None:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="engagement_scope_missing")
    if payload.expires_in_seconds is None:  # pragma: no cover - schema invariant
        raise RuntimeError("approval expiration was not normalized")
    expires_at = timestamp + timedelta(seconds=payload.expires_in_seconds)
    engagement = stored_engagement.entity
    if expires_at > engagement.ends_at:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_CONTENT,
            detail="approval_exceeds_engagement_window",
        )
    approval = Approval(
        engagement_id=action.engagement_id,
        action_type=action.action_type,
        normalized_target=action.normalized_target,
        parameter_digest=action.parameter_digest,
        risk_level=action.risk_level,
        expires_at=expires_at,
        permitted_executions=1,
        approver=principal.identity,
        approved_at=timestamp,
    )
    decision = decide_action(
        action,
        scope=scope,
        config=PolicyConfig(
            maximum_risk=engagement.maximum_risk,
            destructive_actions_enabled=engagement.destructive_actions_enabled,
        ),
        at=timestamp,
        approval=approval,
    )
    if decision.kind is not DecisionKind.ALLOW:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail=decision.reason)
    ApprovalRepository(session).add(approval)
    queued = transition_action(action, ActionState.QUEUED, approval=approval, at=timestamp)
    saved = _save_action(repository, queued, expected_version=stored_action.version)
    record_audit_event(
        session,
        action.engagement_id,
        "approval.granted",
        principal.identity,
        {
            "action_id": action.id,
            "approval_id": approval.id,
            "expires_at": expires_at,
            "permitted_executions": approval.permitted_executions,
            "reason": payload.reason,
        },
        at=timestamp,
    )
    session.commit()
    return ActionMutationResponse(
        action_id=action.id,
        state=saved.entity.state,
        approval=_approval_summary(approval),
    )


@router.get(
    "/actions/{action_id}/approval",
    response_model=ApprovalSummary,
    summary="Get the Approval bound to an Action",
)
def get_action_approval(action_id: str, session: SessionDependency) -> ApprovalSummary:
    stored_action = ActionRepository(session).get(ActionId(action_id))
    if stored_action is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="action_not_found")
    approval_id = stored_action.entity.approval_id
    if approval_id is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="approval_not_found")
    stored_approval = ApprovalRepository(session).get(approval_id)
    if stored_approval is None:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="approval_record_missing")
    return _approval_summary(stored_approval.entity)


@router.post(
    "/actions/{action_id}/cancel",
    response_model=ActionMutationResponse,
    summary="Cancel a non-terminal Action",
)
def cancel_action(
    action_id: str,
    payload: ActionCancelCreate,
    session: SessionDependency,
    principal: OperatorDependency,
) -> ActionMutationResponse:
    repository = ActionRepository(session)
    stored_action = repository.get(ActionId(action_id))
    if stored_action is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="action_not_found")
    action = stored_action.entity
    if action.state in TERMINAL_ACTION_STATES:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="action_already_terminal")
    timestamp = datetime.now(UTC)
    cancelled = transition_action(action, ActionState.CANCELLED, at=timestamp)
    saved = _save_action(repository, cancelled, expected_version=stored_action.version)
    record_audit_event(
        session,
        action.engagement_id,
        "action.cancelled",
        principal.identity,
        {"action_id": action.id, "previous_state": action.state, "reason": payload.reason},
        at=timestamp,
    )
    session.commit()
    return ActionMutationResponse(action_id=action.id, state=saved.entity.state)
