"""Finding review and SARIF report workflow coverage."""

from __future__ import annotations

import json
from pathlib import Path

from tests.api.test_approvals import EVIDENCE_READER_HEADERS, OPERATOR_HEADERS, authenticated_client
from tests.api.test_report_exports import _create_action, _persist_evidence
from tests.api.test_workflow import _create_engagement
from vuln_proof_claw.domain.identifiers import EngagementId, EvidenceId
from vuln_proof_claw.domain.models import Finding
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
            json={"status": "verified", "expected_version": 1},
            headers=OPERATOR_HEADERS,
        )
    assert response.status_code == 409
    assert response.json()["detail"] == "verified findings require at least one evidence record"
