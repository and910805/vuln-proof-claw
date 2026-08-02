"""Auditable Planner/Operator/Verifier automation endpoints."""

from __future__ import annotations

import hashlib
import json
from datetime import UTC, datetime
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session

from vuln_proof_claw.api.audit import record_audit_event
from vuln_proof_claw.api.auth import AuthenticatedPrincipal, require_operator_if_configured
from vuln_proof_claw.api.dependencies import get_session
from vuln_proof_claw.api.schemas.automation import (
    AutomationPlanCreate,
    AutomationPlanSummary,
    ObservationInput,
    PlannedActionSummary,
    VerificationCreate,
    VerificationSummary,
)
from vuln_proof_claw.automation.mutations import MutationPlan, MutationSpec
from vuln_proof_claw.automation.security_checks import (
    ResponseObservation,
    SecurityCheck,
    analyze_cors,
    compare_authentication,
    compare_authorization,
    compare_input_validation,
)
from vuln_proof_claw.domain.action_state import transition_action
from vuln_proof_claw.domain.enums import ActionState
from vuln_proof_claw.domain.errors import DomainValidationError
from vuln_proof_claw.domain.identifiers import EngagementId
from vuln_proof_claw.domain.models import Action, Flow, Task
from vuln_proof_claw.persistence.repositories import (
    ActionRepository,
    EngagementRepository,
    FlowRepository,
    ScopeRepository,
    TaskRepository,
)
from vuln_proof_claw.policy.decision import DecisionKind, PolicyConfig, decide_action
from vuln_proof_claw.policy.risk import classify_risk

router = APIRouter(tags=["automation"])
SessionDependency = Annotated[Session, Depends(get_session)]
OperatorDependency = Annotated[
    AuthenticatedPrincipal, Depends(require_operator_if_configured)
]

_ACTION_TYPES = {
    SecurityCheck.CORS: "public_page_read",
    SecurityCheck.AUTHENTICATION: "active_safe_api_read",
    SecurityCheck.AUTHORIZATION: "active_api_probe",
    SecurityCheck.INPUT_VALIDATION: "active_api_probe",
}


def _observation(item: ObservationInput) -> ResponseObservation:
    return ResponseObservation(
        status_code=item.status_code,
        headers=item.headers,
        body_digest=item.body_digest,
        body_size=item.body_size,
    )


@router.post(
    "/engagements/{engagement_id}/automation-plans",
    response_model=AutomationPlanSummary,
    status_code=status.HTTP_201_CREATED,
    summary="Plan and propose a bounded Planner/Operator/Verifier run",
)
def create_automation_plan(
    engagement_id: str,
    payload: AutomationPlanCreate,
    session: SessionDependency,
    principal: OperatorDependency,
) -> AutomationPlanSummary:
    normalized_id = EngagementId(engagement_id)
    stored_engagement = EngagementRepository(session).get(normalized_id)
    scope = ScopeRepository(session).get(normalized_id)
    if stored_engagement is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="engagement_not_found")
    if scope is None:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="engagement_scope_missing")
    try:
        mutation_plan = (
            MutationPlan(
                target=payload.target,
                mutations=tuple(MutationSpec(**item.model_dump()) for item in payload.mutations),
                reviewed_by=principal.identity,
                review_reason=payload.review_reason,
            )
            if payload.mutations
            else None
        )
    except DomainValidationError as error:
        raise HTTPException(status_code=422, detail=str(error)) from error
    if SecurityCheck.INPUT_VALIDATION in payload.checks and mutation_plan is None:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_CONTENT,
            detail="input_validation_requires_reviewed_mutations",
        )

    timestamp = datetime.now(UTC)
    flow = Flow(
        engagement_id=normalized_id,
        objective=f"Automated bounded security checks for {payload.target}",
    )
    FlowRepository(session).add(flow)
    actions: list[PlannedActionSummary] = []
    action_repository = ActionRepository(session)
    engagement = stored_engagement.entity
    for check in payload.checks:
        task = Task(flow_id=flow.id, title=f"{check.value}: collect comparable evidence")
        TaskRepository(session).add(task)
        action_type = _ACTION_TYPES[check]
        digest_document = {
            "check": check.value,
            "target": payload.target,
            "mutation_plan_digest": mutation_plan.digest if mutation_plan else None,
        }
        parameter_digest = hashlib.sha256(
            json.dumps(digest_document, sort_keys=True, separators=(",", ":")).encode()
        ).hexdigest()
        action = Action(
            engagement_id=normalized_id,
            task_id=task.id,
            action_type=action_type,
            normalized_target=payload.target,
            parameter_digest=parameter_digest,
            risk_level=classify_risk(action_type),
            idempotency_key=f"automation:{flow.id}:{check.value}",
            created_at=timestamp,
        )
        action_repository.add(action)
        stored = action_repository.get(action.id)
        if stored is None:  # pragma: no cover
            raise RuntimeError("automation action was not persisted")
        checking = transition_action(action, ActionState.POLICY_CHECK, at=timestamp)
        checking_stored = action_repository.save(checking, expected_version=stored.version)
        decision = decide_action(
            checking,
            scope=scope,
            config=PolicyConfig(
                maximum_risk=engagement.maximum_risk,
                destructive_actions_enabled=engagement.destructive_actions_enabled,
            ),
            at=timestamp,
        )
        state = {
            DecisionKind.ALLOW: ActionState.QUEUED,
            DecisionKind.APPROVAL_REQUIRED: ActionState.PENDING_APPROVAL,
            DecisionKind.DENY: ActionState.DENIED,
        }[decision.kind]
        saved = action_repository.save(
            transition_action(checking_stored.entity, state, at=timestamp),
            expected_version=checking_stored.version,
        )
        actions.append(
            PlannedActionSummary(
                check=check,
                task_id=task.id,
                action_id=action.id,
                action_type=action_type,
                risk_level=action.risk_level,
                state=saved.entity.state,
                parameter_digest=parameter_digest,
            )
        )
    record_audit_event(
        session,
        normalized_id,
        "automation.plan_created",
        principal.identity,
        {
            "flow_id": flow.id,
            "checks": [item.value for item in payload.checks],
            "mutation_plan_digest": mutation_plan.digest if mutation_plan else None,
            "action_ids": [item.action_id for item in actions],
        },
        at=timestamp,
    )
    session.commit()
    return AutomationPlanSummary(
        flow_id=flow.id,
        engagement_id=engagement_id,
        planner="deterministic-planner-v1",
        operator=principal.identity,
        verifier="deterministic-verifier-v1",
        mutation_plan_digest=mutation_plan.digest if mutation_plan else None,
        actions=tuple(actions),
    )


@router.post(
    "/automation/verify",
    response_model=VerificationSummary,
    summary="Independently verify a bounded response comparison",
)
def verify_observations(payload: VerificationCreate) -> VerificationSummary:
    baseline = _observation(payload.baseline)
    if payload.check is SecurityCheck.CORS:
        if payload.supplied_origin is None:
            raise HTTPException(status_code=422, detail="cors_requires_supplied_origin")
        result = analyze_cors(baseline.headers, supplied_origin=payload.supplied_origin)
    else:
        if payload.comparison is None:
            raise HTTPException(status_code=422, detail="comparison_observation_required")
        comparison = _observation(payload.comparison)
        result = {
            SecurityCheck.AUTHENTICATION: compare_authentication,
            SecurityCheck.AUTHORIZATION: compare_authorization,
            SecurityCheck.INPUT_VALIDATION: compare_input_validation,
        }[payload.check](baseline, comparison)
    return VerificationSummary(
        check=result.check,
        outcome=result.outcome,
        reason=result.reason,
        evidence=result.evidence,
    )
