"""Tests for recording evidence from hand-performed tests."""

from __future__ import annotations

from collections.abc import Generator
from pathlib import Path

import pytest
from sqlalchemy import Engine, select

from tests.agent.support import (
    NOW,
    TARGET_HOST,
    build_engine,
    seed_engagement,
    seed_lead,
    seed_mission,
    session_factory,
)
from vuln_proof_claw.agent.manual import (
    HttpExchange,
    ManualEvidenceRecorder,
    ManualRecordError,
    attach_evidence,
    parse_exchange,
)
from vuln_proof_claw.domain.enums import ActionState
from vuln_proof_claw.domain.errors import DomainValidationError
from vuln_proof_claw.domain.identifiers import MissionId
from vuln_proof_claw.persistence.models import ActionRecord, EvidenceRecord
from vuln_proof_claw.persistence.repositories import ScopeRepository

TRANSCRIPT = f"""
### REQUEST
GET /orders/1 HTTP/1.1
Host: {TARGET_HOST}
Cookie: session=super-secret-value
Authorization: Bearer abcdef123456

### RESPONSE
HTTP/1.1 200 OK
Content-Type: application/json
Set-Cookie: session=rotated-secret

{{"id": 1, "owner": "another-user"}}
"""


@pytest.fixture
def engine(tmp_path: Path) -> Generator[Engine, None, None]:
    yield from build_engine(tmp_path / "manual.db")


def test_a_transcript_is_parsed_into_a_structured_exchange() -> None:
    exchange = parse_exchange(TRANSCRIPT)

    assert exchange.method == "GET"
    assert exchange.target == f"https://{TARGET_HOST}:443/orders/1"
    assert exchange.status_code == 200
    assert dict(exchange.request_headers)["cookie"] == "session=super-secret-value"
    assert "another-user" in exchange.response_body


def test_an_absolute_request_line_does_not_need_a_host_header() -> None:
    exchange = parse_exchange(
        f"""
### REQUEST
POST https://{TARGET_HOST}/login HTTP/1.1

user=a

### RESPONSE
HTTP/1.1 302 Found
Location: /dashboard
"""
    )

    assert exchange.method == "POST"
    assert exchange.status_code == 302


@pytest.mark.parametrize(
    "document",
    [
        "no markers at all",
        "### RESPONSE\nHTTP/1.1 200 OK\n\n### REQUEST\nGET / HTTP/1.1",
        "### REQUEST\n\n### RESPONSE\nHTTP/1.1 200 OK",
        "### REQUEST\nnot a request line\n\n### RESPONSE\nHTTP/1.1 200 OK",
        "### REQUEST\nGET /x HTTP/1.1\nHost: a.test\n\n### RESPONSE\nnot a status line",
    ],
)
def test_malformed_transcripts_are_refused(document: str) -> None:
    with pytest.raises(ManualRecordError):
        parse_exchange(document)


def test_a_request_without_a_resolvable_target_is_refused() -> None:
    with pytest.raises(ManualRecordError):
        parse_exchange("### REQUEST\nGET /x HTTP/1.1\n\n### RESPONSE\nHTTP/1.1 200 OK")


def test_an_oversized_body_is_refused() -> None:
    huge = "a" * (256 * 1024 + 1)
    with pytest.raises(ManualRecordError):
        parse_exchange(
            f"### REQUEST\nGET /x HTTP/1.1\nHost: {TARGET_HOST}\n\n"
            f"### RESPONSE\nHTTP/1.1 200 OK\n\n{huge}"
        )


def test_an_invalid_status_code_is_refused() -> None:
    with pytest.raises(DomainValidationError):
        HttpExchange(method="GET", target=f"https://{TARGET_HOST}/", status_code=999)


def build_recorder(session: object, engagement_id: object) -> ManualEvidenceRecorder:
    scope = ScopeRepository(session).get(engagement_id)  # type: ignore[arg-type]
    assert scope is not None
    return ManualEvidenceRecorder(
        session=session,  # type: ignore[arg-type]
        engagement_id=engagement_id,  # type: ignore[arg-type]
        scope=scope,
        actor="researcher",
    )


def test_recording_appends_to_the_engagement_evidence_chain(engine: Engine) -> None:
    factory = session_factory(engine)
    with factory.begin() as session:
        engagement_id = seed_engagement(session)
        recorder = build_recorder(session, engagement_id)

        first = recorder.record_exchange(parse_exchange(TRANSCRIPT), at=NOW)
        second = recorder.record_exchange(
            parse_exchange(TRANSCRIPT.replace("/orders/1", "/orders/2")), at=NOW
        )

        evidence = list(session.scalars(select(EvidenceRecord)))

    assert len(evidence) == 2
    assert first.previous_digest is None
    assert second.previous_digest == first.digest
    assert first.scope_reason == "scope_allowed"


def test_the_anchor_action_is_recorded_as_already_completed(engine: Engine) -> None:
    """The human performed it; the system must never queue or execute it."""
    factory = session_factory(engine)
    with factory.begin() as session:
        engagement_id = seed_engagement(session)
        build_recorder(session, engagement_id).record_exchange(
            parse_exchange(TRANSCRIPT), at=NOW
        )

        actions = list(session.scalars(select(ActionRecord)))

    assert len(actions) == 1
    assert actions[0].state == ActionState.SUCCEEDED.value


def test_an_out_of_scope_exchange_is_refused(engine: Engine) -> None:
    factory = session_factory(engine)
    with factory.begin() as session:
        engagement_id = seed_engagement(session)
        recorder = build_recorder(session, engagement_id)
        outside = parse_exchange(TRANSCRIPT.replace(TARGET_HOST, "attacker.test"))

        with pytest.raises(ManualRecordError, match="outside the authorized scope"):
            recorder.record_exchange(outside, at=NOW)

        evidence = list(session.scalars(select(EvidenceRecord)))

    assert evidence == []


def test_an_out_of_scope_exchange_can_be_recorded_deliberately(engine: Engine) -> None:
    """An operator may still record one knowingly, for an incident write-up."""
    factory = session_factory(engine)
    with factory.begin() as session:
        engagement_id = seed_engagement(session)
        recorder = build_recorder(session, engagement_id)
        outside = parse_exchange(TRANSCRIPT.replace(TARGET_HOST, "attacker.test"))

        recorded = recorder.record_exchange(outside, at=NOW, allow_out_of_scope=True)

    assert recorded.scope_reason != "scope_allowed"


def test_a_manual_step_hashes_its_screenshot(engine: Engine, tmp_path: Path) -> None:
    screenshot = tmp_path / "shot.png"
    screenshot.write_bytes(b"not really a png")
    factory = session_factory(engine)
    with factory.begin() as session:
        engagement_id = seed_engagement(session)
        mission = seed_mission(session, engagement_id)
        lead = seed_lead(session, engagement_id, MissionId(mission.id))
        recorder = build_recorder(session, engagement_id)

        step = recorder.record_step(
            lead, "以 user_b 身分開啟 user_a 的訂單", screenshot=screenshot, at=NOW
        )

    assert step.screenshot_digest is not None
    assert len(step.screenshot_digest) == 64
    assert step.observation.summary.startswith("以 user_b")


def test_a_missing_screenshot_is_reported(engine: Engine, tmp_path: Path) -> None:
    factory = session_factory(engine)
    with factory.begin() as session:
        engagement_id = seed_engagement(session)
        mission = seed_mission(session, engagement_id)
        lead = seed_lead(session, engagement_id, MissionId(mission.id))
        recorder = build_recorder(session, engagement_id)

        with pytest.raises(ManualRecordError, match="screenshot not found"):
            recorder.record_step(lead, "step", screenshot=tmp_path / "absent.png", at=NOW)


def test_attaching_evidence_does_not_duplicate(engine: Engine) -> None:
    factory = session_factory(engine)
    with factory.begin() as session:
        engagement_id = seed_engagement(session)
        mission = seed_mission(session, engagement_id)
        lead = seed_lead(session, engagement_id, MissionId(mission.id))
        recorder = build_recorder(session, engagement_id)
        recorded = recorder.record_exchange(parse_exchange(TRANSCRIPT), at=NOW)

        once = attach_evidence(lead, (recorded.evidence_id,), at=NOW)
        twice = attach_evidence(once, (recorded.evidence_id,), at=NOW)

    assert once.evidence_ids == (recorded.evidence_id,)
    assert twice.evidence_ids == once.evidence_ids


def test_a_transcript_query_survives_parsing() -> None:
    """A discarded query makes the report self-contradictory and unreproducible."""
    exchange = parse_exchange(
        f"""
### REQUEST
GET /api/getCompanyDisplay?adminUuid=1111 HTTP/1.1
Host: {TARGET_HOST}

### RESPONSE
HTTP/1.1 500 Internal Server Error
Content-Type: application/json

{{"ErrorMessage":"adminUuid is not existing"}}
"""
    )

    assert exchange.query == "adminUuid=1111"
    assert exchange.target == f"https://{TARGET_HOST}:443/api/getCompanyDisplay"
    recorded = exchange.as_canonical_mapping()["request"]
    assert isinstance(recorded, dict)
    assert recorded["query"] == "adminUuid=1111"


def test_a_query_changes_the_recorded_evidence(engine: Engine) -> None:
    """Two requests differing only by query must not produce the same evidence."""
    factory = session_factory(engine)
    with factory.begin() as session:
        engagement_id = seed_engagement(session)
        recorder = build_recorder(session, engagement_id)

        first = recorder.record_exchange(
            parse_exchange(TRANSCRIPT.replace("/orders/1", "/orders?id=1")), at=NOW
        )
        second = recorder.record_exchange(
            parse_exchange(TRANSCRIPT.replace("/orders/1", "/orders?id=2")), at=NOW
        )

    assert first.exchange.query == "id=1"
    assert second.exchange.query == "id=2"
    assert first.digest != second.digest
