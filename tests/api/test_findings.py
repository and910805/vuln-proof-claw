"""Finding review and SARIF report workflow coverage."""

from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path

from tests.api.test_approvals import EVIDENCE_READER_HEADERS, OPERATOR_HEADERS, authenticated_client
from tests.api.test_report_exports import _create_action, _persist_evidence
from tests.api.test_workflow import _create_engagement
from vuln_proof_claw.domain.enums import VerificationMethod
from vuln_proof_claw.domain.identifiers import (
    ActionId,
    EngagementId,
    EvidenceId,
    FindingId,
    new_evidence_id,
)
from vuln_proof_claw.domain.models import Finding
from vuln_proof_claw.evidence.models import EvidenceMetadata
from vuln_proof_claw.evidence.persistence import PersistentEvidenceStore
from vuln_proof_claw.persistence.models import EvidencePayloadRecord, EvidenceRecord
from vuln_proof_claw.persistence.repositories import FindingRepository
from vuln_proof_claw.persistence.session import create_engine, create_session_factory


async def _create_finding(database_path: Path) -> tuple[str, str, str]:
    async with authenticated_client(database_path) as client:
        client.headers.update(OPERATOR_HEADERS)
        engagement_id = await _create_engagement(client)
        action_id = await _create_action(client, engagement_id)
    evidence_id, _ = _persist_evidence(database_path, engagement_id, action_id)
    engine = create_engine(f"sqlite:///{database_path}", pool_pre_ping=False)
    try:
        with create_session_factory(engine).begin() as session:
            finding = Finding(
                engagement_id=EngagementId(engagement_id),
                title="Missing security header",
                vulnerability_class="CWE-693",
                affected_target="https://api.example.test/v1",
                evidence_ids=(EvidenceId(evidence_id),),
            )
            FindingRepository(session).add(finding)
            return engagement_id, str(finding.id), evidence_id
    finally:
        engine.dispose()


def _assert_finding_still_candidate(database_path: Path, finding_id: str) -> None:
    engine = create_engine(f"sqlite:///{database_path}", pool_pre_ping=False)
    try:
        with create_session_factory(engine)() as session:
            stored = FindingRepository(session).get(FindingId(finding_id))
            assert stored is not None
            assert stored.entity.status.value == "candidate"
            assert stored.version == 1
    finally:
        engine.dispose()


async def test_finding_review_requires_version_and_records_audit(tmp_path: Path) -> None:
    database_path = tmp_path / "finding-review.db"
    engagement_id, finding_id, evidence_id = await _create_finding(database_path)
    async with authenticated_client(database_path) as client:
        client.headers.update(OPERATOR_HEADERS)
        reviewed = await client.patch(
            f"/api/v1/engagements/{engagement_id}/findings/{finding_id}",
            json={
                "status": "verified",
                "expected_version": 1,
                "comment": "Evidence reviewed by the operator.",
                "verification_method": "observed",
            },
            headers=OPERATOR_HEADERS,
        )
        stale = await client.patch(
            f"/api/v1/engagements/{engagement_id}/findings/{finding_id}",
            json={"status": "rejected", "expected_version": 1},
            headers=OPERATOR_HEADERS,
        )
        report = await client.get(
            f"/api/v1/engagements/{engagement_id}/report.sarif",
            headers=OPERATOR_HEADERS,
        )
        export = await client.post(
            f"/api/v1/engagements/{engagement_id}/report-exports",
            json={"format": "sarif"},
            headers={**OPERATOR_HEADERS, "Idempotency-Key": "sarif-v1"},
        )
        downloaded = await client.get(
            f"/api/v1/engagements/{engagement_id}/report-exports/"
            f"{export.json()['id']}/download",
            headers=EVIDENCE_READER_HEADERS,
        )
        audit = await client.get(
            f"/api/v1/engagements/{engagement_id}/audit-events",
            headers=OPERATOR_HEADERS,
        )

    assert reviewed.status_code == 200
    assert reviewed.json()["status"] == "verified"
    assert reviewed.json()["version"] == 2
    assert reviewed.json()["evidence_ids"] == [evidence_id]
    assert stale.status_code == 409
    assert stale.json()["detail"] == "finding_version_conflict"
    assert report.status_code == 200
    assert report.headers["content-type"].startswith("application/sarif+json")
    sarif = report.json()
    assert sarif["version"] == "2.1.0"
    assert sarif["runs"][0]["results"][0]["ruleId"] == "CWE-693"
    assert sarif["runs"][0]["results"][0]["properties"]["proofclaw_status"] == "verified"
    assert export.status_code == 201
    assert export.json()["format"] == "sarif"
    assert downloaded.status_code == 200
    assert json.loads(downloaded.content)["version"] == "2.1.0"
    assert audit.json()["items"][0]["event_type"] == "report.export_downloaded"
    assert any(item["event_type"] == "report.export_created" for item in audit.json()["items"])
    assert any(item["event_type"] == "finding.reviewed" for item in audit.json()["items"])


async def test_finding_review_rejects_verified_without_evidence(tmp_path: Path) -> None:
    database_path = tmp_path / "finding-review-no-evidence.db"
    async with authenticated_client(database_path) as client:
        client.headers.update(OPERATOR_HEADERS)
        engagement_id = await _create_engagement(client)
    engine = create_engine(f"sqlite:///{database_path}", pool_pre_ping=False)
    try:
        with create_session_factory(engine).begin() as session:
            finding = Finding(
                engagement_id=EngagementId(engagement_id),
                title="Candidate without evidence",
                vulnerability_class="CWE-693",
                affected_target="https://api.example.test/v1",
            )
            FindingRepository(session).add(finding)
            finding_id = str(finding.id)
    finally:
        engine.dispose()
    async with authenticated_client(database_path) as client:
        response = await client.patch(
            f"/api/v1/engagements/{engagement_id}/findings/{finding_id}",
            json={
                "status": "verified",
                "expected_version": 1,
                "comment": "Evidence reviewed.",
                "verification_method": "observed",
            },
            headers=OPERATOR_HEADERS,
        )
    assert response.status_code == 409
    assert response.json()["detail"] == "verified findings require at least one evidence record"


async def test_finding_review_requires_stated_method_and_rationale(tmp_path: Path) -> None:
    database_path = tmp_path / "finding-review-unstated-basis.db"
    engagement_id, finding_id, _ = await _create_finding(database_path)

    async with authenticated_client(database_path) as client:
        missing_method = await client.patch(
            f"/api/v1/engagements/{engagement_id}/findings/{finding_id}",
            json={
                "status": "verified",
                "expected_version": 1,
                "comment": "The response establishes the claimed issue.",
            },
            headers=OPERATOR_HEADERS,
        )
        blank_rationale = await client.patch(
            f"/api/v1/engagements/{engagement_id}/findings/{finding_id}",
            json={
                "status": "verified",
                "expected_version": 1,
                "comment": "   ",
                "verification_method": "observed",
            },
            headers=OPERATOR_HEADERS,
        )

    assert missing_method.status_code == 409
    assert missing_method.json()["detail"] == "verified findings must state a verification method"
    assert blank_rationale.status_code == 409
    assert blank_rationale.json()["detail"] == "verification_rationale_required"
    _assert_finding_still_candidate(database_path, finding_id)


async def test_finding_review_rejects_evidence_from_another_engagement(tmp_path: Path) -> None:
    database_path = tmp_path / "finding-review-foreign-evidence.db"
    async with authenticated_client(database_path) as client:
        client.headers.update(OPERATOR_HEADERS)
        engagement_id = await _create_engagement(client)
        other_engagement_id = await _create_engagement(client)
        other_action_id = await _create_action(client, other_engagement_id)
    other_evidence_id, _ = _persist_evidence(
        database_path, other_engagement_id, other_action_id
    )
    engine = create_engine(f"sqlite:///{database_path}", pool_pre_ping=False)
    try:
        with create_session_factory(engine).begin() as session:
            finding = Finding(
                engagement_id=EngagementId(engagement_id),
                title="Evidence from another assessment",
                vulnerability_class="CWE-693",
                affected_target="https://api.example.test/v1",
                evidence_ids=(EvidenceId(other_evidence_id),),
            )
            FindingRepository(session).add(finding)
            finding_id = str(finding.id)
    finally:
        engine.dispose()

    async with authenticated_client(database_path) as client:
        response = await client.patch(
            f"/api/v1/engagements/{engagement_id}/findings/{finding_id}",
            json={
                "status": "verified",
                "expected_version": 1,
                "comment": "Evidence reviewed.",
                "verification_method": "observed",
            },
            headers=OPERATOR_HEADERS,
        )
        audit = await client.get(
            f"/api/v1/engagements/{engagement_id}/audit-events", headers=OPERATOR_HEADERS
        )

    assert response.status_code == 409
    assert response.json()["detail"] == "finding_evidence_invalid"
    _assert_finding_still_candidate(database_path, finding_id)
    assert not any(item["event_type"] == "finding.reviewed" for item in audit.json()["items"])


async def test_finding_review_rejects_tampered_raw_evidence(tmp_path: Path) -> None:
    database_path = tmp_path / "finding-review-tampered-evidence.db"
    engagement_id, finding_id, evidence_id = await _create_finding(database_path)
    engine = create_engine(f"sqlite:///{database_path}", pool_pre_ping=False)
    try:
        with create_session_factory(engine).begin() as session:
            payload = session.get(EvidencePayloadRecord, EvidenceId(evidence_id))
            assert payload is not None
            payload.raw_content = b"HTTP/1.1 200 OK\r\n\r\nmodified"
            payload.raw_size = len(payload.raw_content)
    finally:
        engine.dispose()

    async with authenticated_client(database_path) as client:
        response = await client.patch(
            f"/api/v1/engagements/{engagement_id}/findings/{finding_id}",
            json={
                "status": "verified",
                "expected_version": 1,
                "comment": "Evidence reviewed.",
                "verification_method": "observed",
            },
            headers=OPERATOR_HEADERS,
        )
        audit = await client.get(
            f"/api/v1/engagements/{engagement_id}/audit-events", headers=OPERATOR_HEADERS
        )

    assert response.status_code == 409
    assert response.json()["detail"] == "finding_evidence_integrity_failed"
    _assert_finding_still_candidate(database_path, finding_id)
    assert not any(item["event_type"] == "finding.reviewed" for item in audit.json()["items"])


async def test_finding_review_rejects_missing_raw_evidence(tmp_path: Path) -> None:
    database_path = tmp_path / "finding-review-missing-payload.db"
    engagement_id, finding_id, evidence_id = await _create_finding(database_path)
    engine = create_engine(f"sqlite:///{database_path}", pool_pre_ping=False)
    try:
        with create_session_factory(engine).begin() as session:
            payload = session.get(EvidencePayloadRecord, EvidenceId(evidence_id))
            assert payload is not None
            session.delete(payload)
    finally:
        engine.dispose()

    async with authenticated_client(database_path) as client:
        response = await client.patch(
            f"/api/v1/engagements/{engagement_id}/findings/{finding_id}",
            json={
                "status": "verified",
                "expected_version": 1,
                "comment": "Evidence reviewed.",
                "verification_method": "observed",
            },
            headers=OPERATOR_HEADERS,
        )
        audit = await client.get(
            f"/api/v1/engagements/{engagement_id}/audit-events", headers=OPERATOR_HEADERS
        )

    assert response.status_code == 409
    assert response.json()["detail"] == "finding_evidence_invalid"
    _assert_finding_still_candidate(database_path, finding_id)
    assert not any(item["event_type"] == "finding.reviewed" for item in audit.json()["items"])


async def test_finding_review_requires_control_for_differential_claim(tmp_path: Path) -> None:
    database_path = tmp_path / "finding-review-no-control.db"
    engagement_id, finding_id, _ = await _create_finding(database_path)
    engine = create_engine(f"sqlite:///{database_path}", pool_pre_ping=False)
    try:
        with create_session_factory(engine).begin() as session:
            stored = FindingRepository(session).get(FindingId(finding_id))
            assert stored is not None
            # Create a second candidate with the same valid evidence, but a
            # differential claim whose required control has not been captured.
            finding = Finding(
                engagement_id=EngagementId(engagement_id),
                title="Uncontrolled differential claim",
                vulnerability_class="CWE-693",
                affected_target="https://api.example.test/v1",
                evidence_ids=stored.entity.evidence_ids,
                verification_method=VerificationMethod.DIFFERENTIAL,
            )
            FindingRepository(session).add(finding)
            differential_id = str(finding.id)
    finally:
        engine.dispose()

    async with authenticated_client(database_path) as client:
        response = await client.patch(
            f"/api/v1/engagements/{engagement_id}/findings/{differential_id}",
            json={
                "status": "verified",
                "expected_version": 1,
                "comment": "Evidence reviewed.",
            },
            headers=OPERATOR_HEADERS,
        )

    assert response.status_code == 409
    assert response.json()["detail"] == (
        "differential verification requires at least one control evidence record"
    )
    _assert_finding_still_candidate(database_path, differential_id)


def _persist_control_evidence(
    database_path: Path, engagement_id: str, action_id: str, raw: bytes
) -> str:
    evidence_id = new_evidence_id()
    engine = create_engine(f"sqlite:///{database_path}", pool_pre_ping=False)
    try:
        with create_session_factory(engine).begin() as session:
            PersistentEvidenceStore(session).append(
                EvidenceMetadata(
                    evidence_id=evidence_id,
                    engagement_id=EngagementId(engagement_id),
                    action_id=ActionId(action_id),
                    tool_name="http-capture",
                    tool_version="0.0.10",
                    normalized_parameters={"method": "GET"},
                    captured_at=datetime.now(UTC),
                    duration_ms=20,
                    worker_image="test-worker",
                    environment={"transport": "test"},
                    scope_decision="scope_allowed",
                    media_type="application/http",
                ),
                raw,
            )
    finally:
        engine.dispose()
    return str(evidence_id)


async def _differential_candidate_with_control(
    database_path: Path, *, control_raw: bytes | None
) -> tuple[str, str, str, str]:
    engagement_id, _, payload_id = await _create_finding(database_path)
    engine = create_engine(f"sqlite:///{database_path}", pool_pre_ping=False)
    try:
        with create_session_factory(engine)() as session:
            evidence = session.get(EvidenceRecord, EvidenceId(payload_id))
            assert evidence is not None
            original_raw = PersistentEvidenceStore(session).read_raw(payload_id)
            assert original_raw is not None
            owning_action_id = evidence.action_id
    finally:
        engine.dispose()
    control_id = _persist_control_evidence(
        database_path,
        engagement_id,
        owning_action_id,
        original_raw if control_raw is None else control_raw,
    )
    engine = create_engine(f"sqlite:///{database_path}", pool_pre_ping=False)
    try:
        with create_session_factory(engine).begin() as session:
            finding = Finding(
                engagement_id=EngagementId(engagement_id),
                title="Differential claim awaiting control review",
                vulnerability_class="CWE-693",
                affected_target="https://api.example.test/v1",
                evidence_ids=(EvidenceId(payload_id),),
                verification_method=VerificationMethod.DIFFERENTIAL,
            )
            FindingRepository(session).add(finding)
            finding_id = str(finding.id)
    finally:
        engine.dispose()
    return engagement_id, finding_id, payload_id, control_id


async def test_finding_review_binds_verified_differential_control(tmp_path: Path) -> None:
    database_path = tmp_path / "finding-review-control.db"
    engagement_id, finding_id, payload_id, control_id = await _differential_candidate_with_control(
        database_path,
        control_raw=b"HTTP/1.1 403 Forbidden\r\nContent-Type: application/json\r\n\r\n{}",
    )

    async with authenticated_client(database_path) as client:
        reviewed = await client.patch(
            f"/api/v1/engagements/{engagement_id}/findings/{finding_id}",
            json={
                "status": "verified",
                "expected_version": 1,
                "comment": "Compared the observed response with the baseline.",
                "verification_method": "differential",
                "control_evidence_ids": [control_id],
            },
            headers=OPERATOR_HEADERS,
        )
        report = await client.get(
            f"/api/v1/engagements/{engagement_id}/report", headers=OPERATOR_HEADERS
        )
        markdown = await client.get(
            f"/api/v1/engagements/{engagement_id}/report.md", headers=OPERATOR_HEADERS
        )
        html = await client.get(
            f"/api/v1/engagements/{engagement_id}/report.html", headers=OPERATOR_HEADERS
        )
        sarif = await client.get(
            f"/api/v1/engagements/{engagement_id}/report.sarif", headers=OPERATOR_HEADERS
        )

    assert reviewed.status_code == 200
    assert reviewed.json()["status"] == "verified"
    assert reviewed.json()["verification_method"] == "differential"
    assert reviewed.json()["evidence_ids"] == [payload_id]
    assert reviewed.json()["control_evidence_ids"] == [control_id]
    assert report.status_code == 200
    reported = next(item for item in report.json()["findings"] if item["id"] == finding_id)
    assert reported["evidence_ids"] == [payload_id]
    assert reported["control_evidence_ids"] == [control_id]
    assert "| verified |" in markdown.text
    assert payload_id in markdown.text
    assert control_id in markdown.text
    assert "verified" in html.text
    assert payload_id in html.text
    assert control_id in html.text
    sarif_result = next(
        item for item in sarif.json()["runs"][0]["results"]
        if item["properties"]["proofclaw_finding_id"] == finding_id
    )
    assert sarif_result["properties"]["proofclaw_evidence_ids"] == [payload_id]
    assert sarif_result["properties"]["proofclaw_control_evidence_ids"] == [control_id]
    engine = create_engine(f"sqlite:///{database_path}", pool_pre_ping=False)
    try:
        with create_session_factory(engine)() as session:
            stored = FindingRepository(session).get(FindingId(finding_id))
            assert stored is not None
            assert stored.entity.control_evidence_ids == (EvidenceId(control_id),)
    finally:
        engine.dispose()


async def test_finding_review_rejects_identical_payload_and_control_bytes(tmp_path: Path) -> None:
    database_path = tmp_path / "finding-review-identical-control.db"
    engagement_id, finding_id, _, control_id = await _differential_candidate_with_control(
        database_path, control_raw=None
    )

    async with authenticated_client(database_path) as client:
        rejected = await client.patch(
            f"/api/v1/engagements/{engagement_id}/findings/{finding_id}",
            json={
                "status": "verified",
                "expected_version": 1,
                "comment": "Compared the two captured responses.",
                "verification_method": "differential",
                "control_evidence_ids": [control_id],
            },
            headers=OPERATOR_HEADERS,
        )
        audit = await client.get(
            f"/api/v1/engagements/{engagement_id}/audit-events", headers=OPERATOR_HEADERS
        )

    assert rejected.status_code == 409
    assert rejected.json()["detail"] == "finding_control_not_distinct"
    _assert_finding_still_candidate(database_path, finding_id)
    assert not any(item["event_type"] == "finding.reviewed" for item in audit.json()["items"])
