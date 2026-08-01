"""Tests for framework-independent domain value objects."""

from __future__ import annotations

from dataclasses import replace
from datetime import UTC, datetime, timedelta

import pytest

from vuln_proof_claw.domain.enums import FindingStatus, RiskLevel, WorkerState
from vuln_proof_claw.domain.errors import DomainValidationError
from vuln_proof_claw.domain.identifiers import (
    EvidenceId,
    new_action_id,
    new_engagement_id,
    new_project_id,
    new_task_id,
)
from vuln_proof_claw.domain.models import (
    Action,
    Approval,
    Engagement,
    Evidence,
    Finding,
    Project,
    WorkerExecution,
)

NOW = datetime(2026, 7, 30, 12, 0, tzinfo=UTC)
DIGEST = "a" * 64


def make_action(*, risk_level: RiskLevel = RiskLevel.L2) -> Action:
    return Action(
        engagement_id=new_engagement_id(),
        task_id=new_task_id(),
        action_type="http_request",
        normalized_target="https://example.test/api/users",
        parameter_digest=DIGEST,
        risk_level=risk_level,
        idempotency_key="idempotency-1",
        created_at=NOW,
    )


def make_approval(action: Action) -> Approval:
    return Approval(
        engagement_id=action.engagement_id,
        action_type=action.action_type,
        normalized_target=action.normalized_target,
        parameter_digest=action.parameter_digest,
        risk_level=action.risk_level,
        expires_at=NOW + timedelta(hours=1),
        permitted_executions=1,
        approver="security-lead@example.test",
        approved_at=NOW,
    )


def test_risk_levels_define_default_approval_boundary() -> None:
    assert RiskLevel.L0.requires_approval is False
    assert RiskLevel.L1.requires_approval is False
    assert RiskLevel.L2.requires_approval is True
    assert RiskLevel.L3.requires_approval is True
    assert RiskLevel.L4.requires_approval is True


def test_project_rejects_empty_name() -> None:
    with pytest.raises(DomainValidationError, match="name"):
        Project(name=" ", created_at=NOW)


def test_engagement_requires_valid_window() -> None:
    with pytest.raises(DomainValidationError, match="later"):
        Engagement(
            project_id=new_project_id(),
            name="Assessment",
            starts_at=NOW,
            ends_at=NOW,
            created_at=NOW,
        )


def test_destructive_enablement_requires_l4_ceiling() -> None:
    with pytest.raises(DomainValidationError, match="maximum risk"):
        Engagement(
            project_id=new_project_id(),
            name="Assessment",
            starts_at=NOW,
            ends_at=NOW + timedelta(days=1),
            maximum_risk=RiskLevel.L3,
            destructive_actions_enabled=True,
            created_at=NOW,
        )


def test_domain_timestamps_must_be_timezone_aware() -> None:
    with pytest.raises(DomainValidationError, match="timezone-aware"):
        Project(name="Assessment", created_at=datetime(2026, 7, 30))


def test_approval_is_bound_to_exact_protected_properties() -> None:
    action = make_action()
    approval = make_approval(action)

    assert approval.authorizes(action, at=NOW + timedelta(minutes=1))
    assert not approval.authorizes(
        replace(action, normalized_target="https://example.test/api/admin"),
        at=NOW + timedelta(minutes=1),
    )
    assert not approval.authorizes(
        replace(action, parameter_digest="b" * 64),
        at=NOW + timedelta(minutes=1),
    )
    assert not approval.authorizes(action, at=NOW - timedelta(seconds=1))
    assert not approval.authorizes(action, at=approval.expires_at)


def test_exhausted_approval_does_not_authorize_action() -> None:
    action = make_action()
    approval = replace(make_approval(action), consumed_executions=1)

    assert not approval.authorizes(action, at=NOW + timedelta(minutes=1))


def test_evidence_requires_sha256_digest() -> None:
    with pytest.raises(DomainValidationError, match="SHA-256"):
        Evidence(
            action_id=new_action_id(),
            tool_name="http-client",
            tool_version="1.0.0",
            digest="not-a-digest",
            captured_at=NOW,
        )


def test_worker_cleanup_requires_terminal_state() -> None:
    action = make_action()
    with pytest.raises(DomainValidationError, match="terminal Worker state"):
        WorkerExecution(
            request_id="request-1",
            engagement_id=action.engagement_id,
            action_id=action.id,
            runtime_identity="fake-runtime@sha256:test",
            state=WorkerState.RUNNING,
            created_at=NOW,
            updated_at=NOW,
            cleaned_up=True,
        )


def test_verified_finding_requires_evidence() -> None:
    with pytest.raises(DomainValidationError, match="evidence"):
        Finding(
            engagement_id=new_engagement_id(),
            title="Verified issue",
            vulnerability_class="authorization",
            affected_target="https://example.test/api/users",
            status=FindingStatus.VERIFIED,
            created_at=NOW,
        )

    finding = Finding(
        engagement_id=new_engagement_id(),
        title="Verified issue",
        vulnerability_class="authorization",
        affected_target="https://example.test/api/users",
        evidence_ids=(EvidenceId("evidence-1"),),
        status=FindingStatus.VERIFIED,
        created_at=NOW,
    )
    assert finding.status is FindingStatus.VERIFIED
