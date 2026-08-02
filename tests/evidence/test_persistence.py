"""Tests for transactional raw evidence persistence and verification."""

from __future__ import annotations

from collections.abc import Generator
from dataclasses import replace
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
from sqlalchemy import Engine, event

from vuln_proof_claw.domain.enums import RiskLevel
from vuln_proof_claw.domain.identifiers import EngagementId, EvidenceId
from vuln_proof_claw.domain.models import Action, Engagement, Flow, Project, Task
from vuln_proof_claw.evidence.models import EvidenceMetadata
from vuln_proof_claw.evidence.persistence import (
    EvidenceTooLargeError,
    PersistentEvidenceStore,
)
from vuln_proof_claw.evidence.store import DuplicateEvidenceError, InvalidEvidenceError
from vuln_proof_claw.persistence.base import Base
from vuln_proof_claw.persistence.models import EvidencePayloadRecord
from vuln_proof_claw.persistence.repositories import (
    ActionRepository,
    EngagementRepository,
    FlowRepository,
    ProjectRepository,
    TaskRepository,
)
from vuln_proof_claw.persistence.session import create_engine, create_session_factory

NOW = datetime(2026, 8, 1, 12, 0, tzinfo=UTC)


@pytest.fixture
def engine(tmp_path: Path) -> Generator[Engine, None, None]:
    result = create_engine(f"sqlite:///{tmp_path / 'evidence.db'}", pool_pre_ping=False)

    @event.listens_for(result, "connect")
    def enable_foreign_keys(dbapi_connection: object, _connection_record: object) -> None:
        cursor = dbapi_connection.cursor()  # type: ignore[attr-defined]
        cursor.execute("PRAGMA foreign_keys=ON")
        cursor.close()

    Base.metadata.create_all(result)
    yield result
    result.dispose()


def seed_action(engine: Engine) -> tuple[Engagement, Action]:
    project = Project(name="Acme", created_at=NOW)
    engagement = Engagement(
        project_id=project.id,
        name="API assessment",
        starts_at=NOW,
        ends_at=NOW + timedelta(days=1),
        maximum_risk=RiskLevel.L1,
        created_at=NOW,
    )
    flow = Flow(engagement_id=engagement.id, objective="Capture HTTP", created_at=NOW)
    task = Task(flow_id=flow.id, title="Capture response", created_at=NOW)
    action = Action(
        engagement_id=engagement.id,
        task_id=task.id,
        action_type="http_request",
        normalized_target="https://example.test:443/",
        parameter_digest="a" * 64,
        risk_level=RiskLevel.L0,
        idempotency_key="capture-1",
        created_at=NOW,
    )
    session_factory = create_session_factory(engine)
    with session_factory.begin() as session:
        ProjectRepository(session).add(project)
        EngagementRepository(session).add(engagement)
        FlowRepository(session).add(flow)
        TaskRepository(session).add(task)
        ActionRepository(session).add(action)
    return engagement, action


def metadata(engagement: Engagement, action: Action, sequence: int) -> EvidenceMetadata:
    return EvidenceMetadata(
        evidence_id=EvidenceId(f"00000000-0000-7000-8000-{sequence:012d}"),
        engagement_id=engagement.id,
        action_id=action.id,
        tool_name="http-capture",
        tool_version="0.0.3",
        normalized_parameters={"method": "GET", "url": action.normalized_target},
        captured_at=NOW + timedelta(seconds=sequence),
        duration_ms=25,
        worker_image="internal-test",
        environment={"transport": "none"},
        scope_decision="scope_allowed",
        media_type="application/http",
    )


def test_persistent_store_round_trip_and_chain_verification(engine: Engine) -> None:
    engagement, action = seed_action(engine)
    session_factory = create_session_factory(engine)
    with session_factory.begin() as session:
        store = PersistentEvidenceStore(session)
        first = store.append(metadata(engagement, action, 1), b"HTTP/1.1 200 OK\r\n\r\nfirst")
        second = store.append(metadata(engagement, action, 2), b"HTTP/1.1 200 OK\r\n\r\nsecond")
        assert second.previous_digest == first.digest

    with session_factory() as session:
        store = PersistentEvidenceStore(session)
        verification = store.verify_engagement(engagement.id)
        items = store.metadata_for_engagement(engagement.id)

        assert verification.valid
        assert verification.checked_records == 2
        assert store.read_raw(first.metadata.evidence_id) == b"HTTP/1.1 200 OK\r\n\r\nfirst"
        assert [item.digest for item in items] == [first.digest, second.digest]


def test_persistent_store_rejects_duplicates_mismatch_and_oversize(engine: Engine) -> None:
    engagement, action = seed_action(engine)
    item = metadata(engagement, action, 1)
    session_factory = create_session_factory(engine)
    with session_factory.begin() as session:
        store = PersistentEvidenceStore(session, max_raw_bytes=4)
        store.append(item, b"1234")
        with pytest.raises(DuplicateEvidenceError):
            store.append(item, b"1234")
        with pytest.raises(EvidenceTooLargeError):
            store.append(metadata(engagement, action, 2), b"12345")

        mismatched = replace(
            metadata(engagement, action, 3),
            engagement_id=EngagementId("00000000-0000-7000-8000-999999999999"),
        )
        with pytest.raises(InvalidEvidenceError, match="not part"):
            store.append(mismatched, b"1234")


def test_persistent_verification_detects_tampered_raw_content(engine: Engine) -> None:
    engagement, action = seed_action(engine)
    item = metadata(engagement, action, 1)
    session_factory = create_session_factory(engine)
    with session_factory.begin() as session:
        store = PersistentEvidenceStore(session)
        store.append(item, b"original")

    with session_factory.begin() as session:
        payload = session.get(EvidencePayloadRecord, item.evidence_id)
        assert payload is not None
        payload.raw_content = b"tampered"
        payload.raw_size = len(payload.raw_content)

    with session_factory() as session:
        verification = PersistentEvidenceStore(session).verify_engagement(engagement.id)

    assert not verification.valid
    assert verification.reason == "digest_mismatch"
