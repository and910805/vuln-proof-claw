"""Tests that plan progress, usage samples, and control evidence survive a restart."""

from __future__ import annotations

from collections.abc import Generator
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
from sqlalchemy import Engine, event
from sqlalchemy.orm import Session

from vuln_proof_claw.domain.enums import (
    FindingSeverity,
    FindingStatus,
    RiskLevel,
    TaskState,
    UsageKind,
    VerificationMethod,
)
from vuln_proof_claw.domain.models import (
    Action,
    Engagement,
    Evidence,
    Finding,
    Flow,
    Project,
    Task,
    UsageSample,
)
from vuln_proof_claw.domain.plan import claim, resume_point, transition
from vuln_proof_claw.persistence.base import Base
from vuln_proof_claw.persistence.repositories import (
    ActionRepository,
    EngagementRepository,
    EvidenceRepository,
    FindingRepository,
    FlowRepository,
    ProjectRepository,
    TaskRepository,
    UsageSampleRepository,
)
from vuln_proof_claw.persistence.session import create_engine, create_session_factory

NOW = datetime(2026, 8, 26, 12, 0, tzinfo=UTC)
DIGEST = "b" * 64


@pytest.fixture
def engine(tmp_path: Path) -> Generator[Engine, None, None]:
    database_path = tmp_path / "plan.db"
    result = create_engine(f"sqlite:///{database_path}", pool_pre_ping=False)

    @event.listens_for(result, "connect")
    def enable_foreign_keys(dbapi_connection: object, _record: object) -> None:
        cursor = dbapi_connection.cursor()  # type: ignore[attr-defined]
        cursor.execute("PRAGMA foreign_keys=ON")
        cursor.close()

    Base.metadata.create_all(result)
    yield result
    result.dispose()


def seed(session: Session) -> tuple[Engagement, Flow]:
    project = Project(name="Example", created_at=NOW)
    engagement = Engagement(
        project_id=project.id,
        name="Web assessment",
        starts_at=NOW,
        ends_at=NOW + timedelta(days=1),
        maximum_risk=RiskLevel.L4,
        destructive_actions_enabled=False,
        created_at=NOW,
    )
    flow = Flow(engagement_id=engagement.id, objective="Assess the site", created_at=NOW)
    ProjectRepository(session).add(project)
    EngagementRepository(session).add(engagement)
    FlowRepository(session).add(flow)
    session.flush()
    return engagement, flow


def test_an_interrupted_plan_resumes_at_the_step_that_was_running(engine: Engine) -> None:
    factory = create_session_factory(engine)
    with factory.begin() as session:
        _, flow = seed(session)
        tasks = TaskRepository(session)
        first = Task(flow_id=flow.id, title="Enumerate", sequence=0, created_at=NOW)
        second = Task(flow_id=flow.id, title="Verify", sequence=1, created_at=NOW)
        third = Task(flow_id=flow.id, title="Report", sequence=2, created_at=NOW)
        for task in (first, second, third):
            tasks.add(task)
        tasks.save_state(transition(claim(first), TaskState.COMPLETED))
        tasks.save_state(claim(second))
        flow_id = flow.id

    # A fresh process reads the plan back and continues from the same place.
    with factory.begin() as session:
        plan = TaskRepository(session).plan_for_flow(flow_id)
        assert [task.sequence for task in plan] == [0, 1, 2]
        assert plan[0].state is TaskState.COMPLETED
        assert plan[1].state is TaskState.RUNNING
        assert plan[1].attempts == 1
        resumed = resume_point(plan)
        assert resumed is not None
        assert resumed.title == "Verify"


def test_usage_samples_form_a_timeline_with_counts_kept_apart(engine: Engine) -> None:
    factory = create_session_factory(engine)
    with factory.begin() as session:
        engagement, _ = seed(session)
        usage = UsageSampleRepository(session)
        usage.add(
            UsageSample(
                engagement_id=engagement.id,
                kind=UsageKind.LLM_CALL,
                recorded_at=NOW,
                input_tokens=7_729,
                output_tokens=864,
                cost_micros=4_910_000,
                engine="mlx",
                model="Qwen3.8-27B-8bit",
            )
        )
        usage.add(
            UsageSample(
                engagement_id=engagement.id,
                kind=UsageKind.TARGET_COMMAND,
                recorded_at=NOW + timedelta(minutes=5),
                quantity=36,
            )
        )
        usage.add(
            UsageSample(
                engagement_id=engagement.id,
                kind=UsageKind.TOOL_INVOCATION,
                recorded_at=NOW + timedelta(minutes=1),
                quantity=9,
            )
        )
        engagement_id = engagement.id

    with factory.begin() as session:
        usage = UsageSampleRepository(session)
        timeline = usage.timeline(engagement_id)
        assert [sample.kind for sample in timeline] == [
            UsageKind.LLM_CALL,
            UsageKind.TOOL_INVOCATION,
            UsageKind.TARGET_COMMAND,
        ]
        assert timeline[0].engine == "mlx"
        totals = usage.totals(engagement_id)
        # Commands issued at the target and model calls must not be one number.
        assert totals[UsageKind.TARGET_COMMAND.value] == 36
        assert totals[UsageKind.TOOL_INVOCATION.value] == 9
        assert totals[UsageKind.LLM_CALL.value] == 1
        assert totals["cost_micros"] == 4_910_000


def test_control_evidence_round_trips_separately_from_the_payload(engine: Engine) -> None:
    factory = create_session_factory(engine)
    with factory.begin() as session:
        engagement, flow = seed(session)
        task = Task(flow_id=flow.id, title="Verify traversal", created_at=NOW)
        TaskRepository(session).add(task)
        action = Action(
            engagement_id=engagement.id,
            task_id=task.id,
            action_type="exploit_attempt",
            normalized_target="https://example.test/wp-admin/admin-ajax.php",
            parameter_digest=DIGEST,
            risk_level=RiskLevel.L2,
            idempotency_key="traversal-1",
            created_at=NOW,
        )
        ActionRepository(session).add(action)
        session.flush()
        evidence_repository = EvidenceRepository(session)
        payload = Evidence(
            action_id=action.id,
            tool_name="curl",
            tool_version="8.5.0",
            digest=DIGEST,
            captured_at=NOW,
        )
        control = Evidence(
            action_id=action.id,
            tool_name="curl",
            tool_version="8.5.0",
            digest="c" * 64,
            previous_digest=DIGEST,
            captured_at=NOW,
        )
        evidence_repository.add(payload)
        evidence_repository.add(control)
        finding = Finding(
            engagement_id=engagement.id,
            title="Unauthenticated arbitrary file read",
            vulnerability_class="path_traversal",
            affected_target="https://example.test/wp-admin/admin-ajax.php",
            evidence_ids=(payload.id,),
            control_evidence_ids=(control.id,),
            verification_method=VerificationMethod.DIFFERENTIAL,
            cwe_id="CWE-22",
            severity=FindingSeverity.CRITICAL,
            status=FindingStatus.PENDING_VERIFICATION,
            created_at=NOW,
        )
        FindingRepository(session).add(finding)
        finding_id = finding.id

    with factory.begin() as session:
        stored = FindingRepository(session).get(finding_id)
        assert stored is not None
        restored = stored.entity
        assert restored.evidence_ids != restored.control_evidence_ids
        assert len(restored.evidence_ids) == 1
        assert len(restored.control_evidence_ids) == 1
        assert restored.verification_method is VerificationMethod.DIFFERENTIAL
        assert restored.cwe_id == "CWE-22"
