"""Stored HTTP observations must remain bound to their authorized capture."""

from __future__ import annotations

import json
from collections.abc import Generator
from datetime import timedelta
from pathlib import Path

import pytest
from sqlalchemy import Engine
from sqlalchemy.orm import Session

from tests.execution.test_http_capture import (
    NOW,
    FakeTransport,
    seed_approved_capture_action,
    seed_capture_action,
)
from vuln_proof_claw.agent.manual import MANUAL_TOOL_NAME
from vuln_proof_claw.domain.identifiers import EngagementId, EvidenceId, new_evidence_id
from vuln_proof_claw.evidence.http_capture_validation import (
    PersistedCaptureValidationError,
    load_authorized_http_capture,
)
from vuln_proof_claw.evidence.models import EvidenceMetadata
from vuln_proof_claw.evidence.persistence import PersistentEvidenceStore
from vuln_proof_claw.execution.http_capture import (
    HttpCaptureCoordinator,
    HttpCaptureRequest,
    capture_parameter_digest,
)
from vuln_proof_claw.persistence.base import Base
from vuln_proof_claw.persistence.models import ActionRecord, ApprovalRecord, EvidencePayloadRecord
from vuln_proof_claw.persistence.session import create_engine, create_session_factory


@pytest.fixture
def engine(tmp_path: Path) -> Generator[Engine, None, None]:
    result = create_engine(f"sqlite:///{tmp_path / 'stored-captures.db'}", pool_pre_ping=False)
    Base.metadata.create_all(result)
    yield result
    result.dispose()


def _capture(
    engine: Engine, *, query: str = ""
) -> tuple[EngagementId, EvidenceId, HttpCaptureRequest]:
    engagement, action, request = seed_capture_action(engine)
    factory = create_session_factory(engine)
    if query:
        request = HttpCaptureRequest(
            action_id=action.id,
            method=request.method,
            target=request.target,
            headers=request.headers,
            query=query,
        )
        with factory.begin() as session:
            row = session.get(ActionRecord, action.id)
            assert row is not None
            row.query = request.query
            row.parameter_digest = capture_parameter_digest(request)
    with factory.begin() as session:
        result = HttpCaptureCoordinator(session, FakeTransport()).capture(request, at=NOW)
        assert result.evidence is not None
        evidence_id = result.evidence.metadata.evidence_id
    return engagement.id, evidence_id, request


def _append_with_changed_provenance(  # noqa: PLR0913 - each provenance field is explicit
    session: Session,
    engagement_id: EngagementId,
    source_evidence_id: EvidenceId,
    request: HttpCaptureRequest,
    *,
    tool_name: str = "http-capture",
    parameters: dict[str, object] | None = None,
    scope_decision: str | None = None,
) -> EvidenceId:
    """Create an intact chain link whose claimed provenance differs from the capture."""
    source = session.get(EvidencePayloadRecord, source_evidence_id)
    assert source is not None
    original = json.loads(bytes(source.canonical_metadata))
    evidence_id = new_evidence_id()
    PersistentEvidenceStore(session).append(
        EvidenceMetadata(
            evidence_id=evidence_id,
            engagement_id=engagement_id,
            action_id=request.action_id,
            tool_name=tool_name,
            tool_version="test/v1",
            normalized_parameters=(
                original["normalized_parameters"] if parameters is None else parameters
            ),
            captured_at=NOW,
            duration_ms=12,
            worker_image="test-copied-capture",
            environment={"transport": "test"},
            scope_decision=original["scope_decision"] if scope_decision is None else scope_decision,
            media_type=original["media_type"],
        ),
        bytes(source.raw_content),
    )
    return evidence_id


def test_loader_recovers_a_real_capture_including_its_query(engine: Engine) -> None:
    engagement_id, evidence_id, request = _capture(engine, query="page=2")
    with create_session_factory(engine)() as session:
        loaded = load_authorized_http_capture(
            session, engagement_id, evidence_id, expected_target=request.target
        )
        assert PersistentEvidenceStore(session).verify_engagement(engagement_id).valid

    assert loaded.evidence_id == evidence_id
    assert len(loaded.evidence_digest) == 64
    assert loaded.request == request
    assert loaded.response.status_code == 200
    assert loaded.response.body == b"hello"


def test_loader_rejects_a_claim_about_a_different_target(engine: Engine) -> None:
    engagement_id, evidence_id, _request = _capture(engine)
    with (
        create_session_factory(engine)() as session,
        pytest.raises(
            PersistedCaptureValidationError, match="capture_target_or_parameters_mismatch"
        ),
    ):
        load_authorized_http_capture(
            session,
            engagement_id,
            evidence_id,
            expected_target="https://example.test:443/other",
        )


@pytest.mark.parametrize(
    ("field", "changed"),
    [
        ("normalized_target", "https://example.test:443/other"),
        ("query", "page=3"),
    ],
)
def test_loader_rejects_action_target_or_query_drift(
    engine: Engine, field: str, changed: str
) -> None:
    engagement_id, evidence_id, request = _capture(engine, query="page=2")
    factory = create_session_factory(engine)
    with factory.begin() as session:
        action = session.get(ActionRecord, request.action_id)
        assert action is not None
        setattr(action, field, changed)
    with factory() as session:
        assert PersistentEvidenceStore(session).verify_engagement(engagement_id).valid
        with pytest.raises(
            PersistedCaptureValidationError, match="capture_target_or_parameters_mismatch"
        ):
            load_authorized_http_capture(session, engagement_id, evidence_id)


def test_loader_rejects_evidence_from_an_action_that_no_longer_succeeded(engine: Engine) -> None:
    engagement_id, evidence_id, request = _capture(engine)
    factory = create_session_factory(engine)
    with factory.begin() as session:
        action = session.get(ActionRecord, request.action_id)
        assert action is not None
        action.state = "failed"
    with factory() as session:
        assert PersistentEvidenceStore(session).verify_engagement(engagement_id).valid
        with pytest.raises(PersistedCaptureValidationError, match="capture_action_not_succeeded"):
            load_authorized_http_capture(session, engagement_id, evidence_id)


@pytest.mark.parametrize("change", ["target", "scope_decision"])
def test_loader_rejects_intact_evidence_with_false_metadata(engine: Engine, change: str) -> None:
    engagement_id, evidence_id, request = _capture(engine)
    factory = create_session_factory(engine)
    with factory.begin() as session:
        parameters = None
        scope_decision = None
        if change == "target":
            source = session.get(EvidencePayloadRecord, evidence_id)
            assert source is not None
            parameters = dict(json.loads(bytes(source.canonical_metadata))["normalized_parameters"])
            parameters["target"] = "https://example.test:443/other"
        else:
            scope_decision = "scope_denied"
        forged_id = _append_with_changed_provenance(
            session,
            engagement_id,
            evidence_id,
            request,
            parameters=parameters,
            scope_decision=scope_decision,
        )
    with factory() as session:
        assert PersistentEvidenceStore(session).verify_engagement(engagement_id).valid
        with pytest.raises(PersistedCaptureValidationError, match="capture_metadata_mismatch"):
            load_authorized_http_capture(session, engagement_id, forged_id)


def test_loader_does_not_promote_a_manual_source_with_capture_shaped_bytes(
    engine: Engine,
) -> None:
    engagement_id, evidence_id, request = _capture(engine)
    factory = create_session_factory(engine)
    with factory.begin() as session:
        manual_id = _append_with_changed_provenance(
            session, engagement_id, evidence_id, request, tool_name=MANUAL_TOOL_NAME
        )
    with factory() as session:
        assert PersistentEvidenceStore(session).verify_engagement(engagement_id).valid
        with pytest.raises(PersistedCaptureValidationError, match="capture_source_untrusted"):
            load_authorized_http_capture(session, engagement_id, manual_id)


def test_loader_checks_the_approval_against_the_executed_action(engine: Engine) -> None:
    action, approval, request = seed_approved_capture_action(
        engine, expires_at=NOW + timedelta(minutes=10)
    )
    factory = create_session_factory(engine)
    with factory.begin() as session:
        result = HttpCaptureCoordinator(session, FakeTransport()).capture(request, at=NOW)
        assert result.evidence is not None
        evidence_id = result.evidence.metadata.evidence_id
    with factory() as session:
        load_authorized_http_capture(session, action.engagement_id, evidence_id)
    with factory.begin() as session:
        row = session.get(ApprovalRecord, approval.id)
        assert row is not None
        row.normalized_target = "https://example.test:443/other"
    with factory() as session:
        assert PersistentEvidenceStore(session).verify_engagement(action.engagement_id).valid
        with pytest.raises(PersistedCaptureValidationError, match="capture_approval_mismatch"):
            load_authorized_http_capture(session, action.engagement_id, evidence_id)


def test_loader_rejects_a_changed_raw_capture_even_when_its_size_is_updated(engine: Engine) -> None:
    engagement_id, evidence_id, _request = _capture(engine)
    factory = create_session_factory(engine)
    with factory.begin() as session:
        payload = session.get(EvidencePayloadRecord, evidence_id)
        assert payload is not None
        payload.raw_content = b'{"capture_schema":"http-v1","forged":true}'
        payload.raw_size = len(payload.raw_content)
    with factory() as session:
        assert not PersistentEvidenceStore(session).verify_engagement(engagement_id).valid
        with pytest.raises(PersistedCaptureValidationError, match="capture_chain_invalid"):
            load_authorized_http_capture(session, engagement_id, evidence_id)
