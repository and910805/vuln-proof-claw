"""Tests for domain-to-relational repository adapters."""

from __future__ import annotations

from collections.abc import Generator
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
from sqlalchemy import Engine, event
from sqlalchemy.orm import Session

from vuln_proof_claw.domain.action_state import transition_action
from vuln_proof_claw.domain.enums import ActionState, ArtifactKind, FindingStatus, RiskLevel
from vuln_proof_claw.domain.models import (
    Action,
    Approval,
    Artifact,
    Engagement,
    Evidence,
    Finding,
    Flow,
    Project,
    Task,
)
from vuln_proof_claw.persistence.base import Base
from vuln_proof_claw.persistence.repositories import (
    ActionRepository,
    ApprovalRepository,
    ArtifactRepository,
    ConcurrentUpdateError,
    EngagementRepository,
    EvidenceRepository,
    FindingRepository,
    FlowRepository,
    ProjectRepository,
    TaskRepository,
)
from vuln_proof_claw.persistence.session import create_engine, create_session_factory

NOW = datetime(2026, 7, 30, 12, 0, tzinfo=UTC)
DIGEST = "a" * 64


@pytest.fixture
def engine(tmp_path: Path) -> Generator[Engine, None, None]:
    database_path = tmp_path / "repositories.db"
    result = create_engine(f"sqlite:///{database_path}", pool_pre_ping=False)

    @event.listens_for(result, "connect")
    def enable_foreign_keys(dbapi_connection: object, _connection_record: object) -> None:
        cursor = dbapi_connection.cursor()  # type: ignore[attr-defined]
        cursor.execute("PRAGMA foreign_keys=ON")
        cursor.close()

    Base.metadata.create_all(result)
    yield result
    result.dispose()


def add_hierarchy(session: Session) -> tuple[Engagement, Task]:
    project = Project(name="Example", created_at=NOW)
    engagement = Engagement(
        project_id=project.id,
        name="Web/API assessment",
        starts_at=NOW,
        ends_at=NOW + timedelta(days=1),
        maximum_risk=RiskLevel.L4,
        destructive_actions_enabled=True,
        created_at=NOW,
    )
    flow = Flow(engagement_id=engagement.id, objective="Assess the API", created_at=NOW)
    task = Task(flow_id=flow.id, title="Check authorization", created_at=NOW)
    ProjectRepository(session).add(project)
    EngagementRepository(session).add(engagement)
    FlowRepository(session).add(flow)
    TaskRepository(session).add(task)
    session.flush()
    return engagement, task


def make_action(engagement: Engagement, task: Task) -> Action:
    return Action(
        engagement_id=engagement.id,
        task_id=task.id,
        action_type="http_request",
        normalized_target="https://example.test/api/users",
        parameter_digest=DIGEST,
        risk_level=RiskLevel.L0,
        idempotency_key="action-1",
        created_at=NOW,
    )


def test_hierarchy_and_action_round_trip(engine: Engine) -> None:
    session_factory = create_session_factory(engine)
    with session_factory.begin() as session:
        engagement, task = add_hierarchy(session)
        action = make_action(engagement, task)
        ActionRepository(session).add(action)

    with session_factory() as session:
        stored_engagement = EngagementRepository(session).get(engagement.id)
        stored_task = TaskRepository(session).get(task.id)
        stored_action = ActionRepository(session).get(action.id)

        assert stored_engagement is not None
        assert stored_engagement.entity == engagement
        assert stored_engagement.version == 1
        assert stored_task == task
        assert stored_action is not None
        assert stored_action.entity == action
        assert stored_action.version == 1


def test_action_repository_rejects_stale_version(engine: Engine) -> None:
    session_factory = create_session_factory(engine)
    with session_factory.begin() as setup:
        engagement, task = add_hierarchy(setup)
        action = make_action(engagement, task)
        ActionRepository(setup).add(action)

    first = session_factory()
    second = session_factory()
    try:
        first_copy = ActionRepository(first).get(action.id)
        second_copy = ActionRepository(second).get(action.id)
        assert first_copy is not None
        assert second_copy is not None

        first_updated = transition_action(first_copy.entity, ActionState.POLICY_CHECK, at=NOW)
        first_result = ActionRepository(first).save(
            first_updated,
            expected_version=first_copy.version,
        )
        first.commit()
        assert first_result.version == 2

        second_updated = transition_action(second_copy.entity, ActionState.CANCELLED, at=NOW)
        with pytest.raises(ConcurrentUpdateError):
            ActionRepository(second).save(
                second_updated,
                expected_version=second_copy.version,
            )
    finally:
        first.close()
        second.close()


def test_approval_evidence_artifact_and_finding_round_trip(engine: Engine) -> None:
    session_factory = create_session_factory(engine)
    with session_factory.begin() as session:
        engagement, task = add_hierarchy(session)
        action = make_action(engagement, task)
        approval = Approval(
            engagement_id=engagement.id,
            action_type=action.action_type,
            normalized_target=action.normalized_target,
            parameter_digest=action.parameter_digest,
            risk_level=action.risk_level,
            expires_at=NOW + timedelta(hours=1),
            permitted_executions=1,
            approver="security-lead@example.test",
            approved_at=NOW,
        )
        ApprovalRepository(session).add(approval)
        ActionRepository(session).add(action)
        evidence = Evidence(
            action_id=action.id,
            tool_name="http-client",
            tool_version="1.0.0",
            digest=DIGEST,
            captured_at=NOW,
        )
        EvidenceRepository(session).add(evidence)
        artifact = Artifact(
            action_id=action.id,
            kind=ArtifactKind.HTTP_ARCHIVE,
            media_type="application/json",
            storage_reference="artifacts/request.har",
            digest="b" * 64,
            created_at=NOW,
        )
        ArtifactRepository(session).add(artifact)
        finding = Finding(
            engagement_id=engagement.id,
            title="Authorization issue",
            vulnerability_class="broken_access_control",
            affected_target=action.normalized_target,
            evidence_ids=(evidence.id,),
            status=FindingStatus.VERIFIED,
            created_at=NOW,
        )
        FindingRepository(session).add(finding)

    with session_factory() as session:
        stored_approval = ApprovalRepository(session).get(approval.id)
        stored_evidence = EvidenceRepository(session).for_action(action.id)
        stored_artifact = ArtifactRepository(session).get(artifact.id)
        stored_finding = FindingRepository(session).get(finding.id)

        assert stored_approval is not None
        assert stored_approval.entity == approval
        assert stored_evidence == (evidence,)
        assert stored_artifact == artifact
        assert stored_finding is not None
        assert stored_finding.entity == finding
