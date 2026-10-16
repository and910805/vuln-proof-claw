"""Reports must not publish verified claims after their proof becomes invalid."""

from __future__ import annotations

from pathlib import Path

import pytest
from sqlalchemy import delete, insert, update

from tests.api.test_approvals import (
    EVIDENCE_READER_HEADERS,
    OPERATOR_HEADERS,
    authenticated_client,
)
from tests.api.test_findings import _create_finding
from tests.api.test_report_exports import _create_action, _persist_evidence
from tests.api.test_workflow import _create_engagement
from vuln_proof_claw.api.routes.reports import build_engagement_report
from vuln_proof_claw.api.schemas.reports import EvidenceIntegrity
from vuln_proof_claw.domain.identifiers import EvidenceId
from vuln_proof_claw.persistence.models import (
    EvidencePayloadRecord,
    EvidenceRecord,
    FindingRecord,
    finding_evidence,
)
from vuln_proof_claw.persistence.session import create_engine, create_session_factory
from vuln_proof_claw.reporting.bundle import build_disclosure_bundle


async def _verify_finding(database_path: Path) -> tuple[str, str, str]:
    engagement_id, finding_id, evidence_id = await _create_finding(database_path)
    async with authenticated_client(database_path) as client:
        response = await client.patch(
            f"/api/v1/engagements/{engagement_id}/findings/{finding_id}",
            json={
                "status": "verified",
                "expected_version": 1,
                "verification_method": "observed",
                "comment": "The captured header directly supports this claim.",
            },
            headers=OPERATOR_HEADERS,
        )
    assert response.status_code == 200
    return engagement_id, finding_id, evidence_id


@pytest.mark.parametrize("damage", ["missing_link", "foreign_link", "tampered_payload"])
async def test_verified_report_and_bundle_refuse_invalid_linked_evidence(
    tmp_path: Path,
    damage: str,
) -> None:
    database_path = tmp_path / f"verified-{damage}.db"
    engagement_id, finding_id, evidence_id = await _verify_finding(database_path)
    export_ids: dict[str, str] = {}
    async with authenticated_client(database_path) as client:
        for export_format in ("json", "markdown", "sarif"):
            created = await client.post(
                f"/api/v1/engagements/{engagement_id}/report-exports",
                json={"format": export_format},
                headers={**OPERATOR_HEADERS, "Idempotency-Key": f"before-{damage}-{export_format}"},
            )
            assert created.status_code == 201
            export_ids[export_format] = created.json()["id"]
            valid_download = await client.get(
                f"/api/v1/engagements/{engagement_id}/report-exports/{created.json()['id']}/download",
                headers=EVIDENCE_READER_HEADERS,
            )
            assert valid_download.status_code == 200
            valid_replay = await client.post(
                f"/api/v1/engagements/{engagement_id}/report-exports",
                json={"format": export_format},
                headers={**OPERATOR_HEADERS, "Idempotency-Key": f"before-{damage}-{export_format}"},
            )
            assert valid_replay.status_code == 200
    foreign_evidence_id: str | None = None
    if damage == "foreign_link":
        async with authenticated_client(database_path) as client:
            client.headers.update(OPERATOR_HEADERS)
            other_engagement = await _create_engagement(client)
            other_action = await _create_action(client, other_engagement)
        foreign_evidence_id, _ = _persist_evidence(database_path, other_engagement, other_action)

    engine = create_engine(f"sqlite:///{database_path}", pool_pre_ping=False)
    try:
        with create_session_factory(engine).begin() as session:
            if damage == "missing_link":
                session.execute(
                    delete(finding_evidence).where(finding_evidence.c.finding_id == finding_id)
                )
            elif damage == "foreign_link":
                assert foreign_evidence_id is not None
                session.execute(
                    update(finding_evidence)
                    .where(finding_evidence.c.finding_id == finding_id)
                    .values(evidence_id=foreign_evidence_id)
                )
            else:
                payload = session.get(EvidencePayloadRecord, EvidenceId(evidence_id))
                assert payload is not None
                payload.raw_content = b"changed after verification"
                payload.raw_size = len(payload.raw_content)
    finally:
        engine.dispose()

    async with authenticated_client(database_path) as client:
        report_responses = [
            await client.get(
                f"/api/v1/engagements/{engagement_id}/{suffix}", headers=OPERATOR_HEADERS
            )
            for suffix in (
                "report",
                "report.md",
                "report.html",
                "report.sarif",
                "report.bundle.zip",
            )
        ]
        saved_responses = [
            await client.get(
                f"/api/v1/engagements/{engagement_id}/report-exports/{export_id}/download",
                headers=EVIDENCE_READER_HEADERS,
            )
            for export_id in export_ids.values()
        ]
        replay_responses = [
            await client.post(
                f"/api/v1/engagements/{engagement_id}/report-exports",
                json={"format": export_format},
                headers={**OPERATOR_HEADERS, "Idempotency-Key": f"before-{damage}-{export_format}"},
            )
            for export_format in export_ids
        ]

    expected = (
        "finding_evidence_integrity_failed"
        if damage == "tampered_payload"
        else "finding_evidence_invalid"
    )
    for response in (*report_responses, *saved_responses, *replay_responses):
        assert response.status_code == 409
        assert response.json()["detail"] == expected


async def test_sarif_reports_only_verified_findings(tmp_path: Path) -> None:
    database_path = tmp_path / "sarif-verification.db"
    engagement_id, finding_id, _ = await _create_finding(database_path)
    path = f"/api/v1/engagements/{engagement_id}"

    async with authenticated_client(database_path) as client:
        candidate = await client.get(f"{path}/report.sarif", headers=OPERATOR_HEADERS)
        pending_review = await client.patch(
            f"{path}/findings/{finding_id}",
            json={"status": "pending_verification", "expected_version": 1},
            headers=OPERATOR_HEADERS,
        )
        pending = await client.get(f"{path}/report.sarif", headers=OPERATOR_HEADERS)
        verified_review = await client.patch(
            f"{path}/findings/{finding_id}",
            json={
                "status": "verified",
                "expected_version": 2,
                "verification_method": "observed",
                "comment": "The captured header directly supports this claim.",
            },
            headers=OPERATOR_HEADERS,
        )
        verified = await client.get(f"{path}/report.sarif", headers=OPERATOR_HEADERS)
        rejected_review = await client.patch(
            f"{path}/findings/{finding_id}",
            json={"status": "rejected", "expected_version": 3},
            headers=OPERATOR_HEADERS,
        )
        rejected = await client.get(f"{path}/report.sarif", headers=OPERATOR_HEADERS)
        json_report = await client.get(f"{path}/report", headers=OPERATOR_HEADERS)

    assert pending_review.status_code == 200
    assert verified_review.status_code == 200
    assert rejected_review.status_code == 200
    assert candidate.json()["runs"][0]["results"] == []
    assert pending.json()["runs"][0]["results"] == []
    assert [
        item["properties"]["proofclaw_status"] for item in verified.json()["runs"][0]["results"]
    ] == ["verified"]
    assert rejected.json()["runs"][0]["results"] == []
    assert json_report.json()["findings"][0]["status"] == "rejected"


async def test_saved_verified_exports_fail_closed_after_finding_rejection(tmp_path: Path) -> None:
    database_path = tmp_path / "rejected-after-export.db"
    engagement_id, finding_id, _ = await _verify_finding(database_path)
    path = f"/api/v1/engagements/{engagement_id}"
    async with authenticated_client(database_path) as client:
        export_ids: list[str] = []
        for export_format in ("json", "markdown", "sarif"):
            created = await client.post(
                f"{path}/report-exports",
                json={"format": export_format},
                headers={**OPERATOR_HEADERS, "Idempotency-Key": f"pre-rejection-{export_format}"},
            )
            assert created.status_code == 201
            export_ids.append(created.json()["id"])
        rejected = await client.patch(
            f"{path}/findings/{finding_id}",
            json={"status": "rejected", "expected_version": 2},
            headers=OPERATOR_HEADERS,
        )
        downloads = [
            await client.get(
                f"{path}/report-exports/{export_id}/download", headers=EVIDENCE_READER_HEADERS
            )
            for export_id in export_ids
        ]
    assert rejected.status_code == 200
    for response in downloads:
        assert response.status_code == 409
        assert response.json()["detail"] == "report_export_revalidation_failed"


async def test_differential_report_rejects_identical_raw_control(tmp_path: Path) -> None:
    database_path = tmp_path / "identical-differential-control.db"
    engagement_id, finding_id, evidence_id = await _verify_finding(database_path)
    engine = create_engine(f"sqlite:///{database_path}", pool_pre_ping=False)
    try:
        with create_session_factory(engine)() as session:
            evidence = session.get(EvidenceRecord, EvidenceId(evidence_id))
            assert evidence is not None
            action_id = evidence.action_id
    finally:
        engine.dispose()
    control_id, _ = _persist_evidence(database_path, engagement_id, action_id)
    engine = create_engine(f"sqlite:///{database_path}", pool_pre_ping=False)
    try:
        with create_session_factory(engine).begin() as session:
            session.execute(
                update(FindingRecord)
                .where(FindingRecord.id == finding_id)
                .values(verification_method="differential")
            )
            session.execute(
                insert(finding_evidence).values(
                    finding_id=finding_id,
                    evidence_id=control_id,
                    role="control",
                )
            )
    finally:
        engine.dispose()

    async with authenticated_client(database_path) as client:
        report = await client.get(
            f"/api/v1/engagements/{engagement_id}/report", headers=OPERATOR_HEADERS
        )
        bundle = await client.get(
            f"/api/v1/engagements/{engagement_id}/report.bundle.zip",
            headers=OPERATOR_HEADERS,
        )
    for response in (report, bundle):
        assert response.status_code == 409
        assert response.json()["detail"] == "finding_evidence_invalid"


@pytest.mark.parametrize(
    "damage", ["invalid_integrity", "missing_method", "missing_control", "overlap"]
)
async def test_bundle_builder_refuses_invalid_verified_claim(
    tmp_path: Path,
    damage: str,
) -> None:
    database_path = tmp_path / f"bundle-builder-{damage}.db"
    engagement_id, _, _ = await _verify_finding(database_path)
    engine = create_engine(f"sqlite:///{database_path}", pool_pre_ping=False)
    try:
        with create_session_factory(engine)() as session:
            report = build_engagement_report(session, engagement_id)
    finally:
        engine.dispose()
    if damage == "invalid_integrity":
        invalid = report.model_copy(
            update={
                "evidence_integrity": EvidenceIntegrity(
                    status="invalid", checked_records=1, reason="digest_mismatch"
                )
            }
        )
    else:
        finding = report.findings[0]
        updates_by_damage: dict[str, dict[str, object]] = {
            "missing_method": {"verification_method": None},
            "missing_control": {"verification_method": "differential"},
            "overlap": {"control_evidence_ids": finding.evidence_ids},
        }
        updates = updates_by_damage[damage]
        invalid = report.model_copy(update={"findings": (finding.model_copy(update=updates),)})

    with pytest.raises(ValueError, match="valid linked evidence"):
        build_disclosure_bundle(invalid, markdown=b"", html=b"", sarif=b"")
