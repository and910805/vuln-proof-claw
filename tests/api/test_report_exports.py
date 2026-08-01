"""End-to-end coverage for immutable reports and guarded raw evidence access."""

from __future__ import annotations

import hashlib
from datetime import UTC, datetime
from pathlib import Path

from httpx import AsyncClient

from tests.api.test_approvals import (
    EVIDENCE_READER_HEADERS,
    OPERATOR_HEADERS,
    authenticated_client,
)
from tests.api.test_console import console_client
from tests.api.test_workflow import _create_engagement, _create_task
from vuln_proof_claw.domain.identifiers import ActionId, EngagementId, EvidenceId, new_evidence_id
from vuln_proof_claw.evidence.models import EvidenceMetadata
from vuln_proof_claw.evidence.persistence import PersistentEvidenceStore
from vuln_proof_claw.persistence.models import EvidencePayloadRecord, ReportExportRecord
from vuln_proof_claw.persistence.session import create_engine, create_session_factory


async def _create_action(client: AsyncClient, engagement_id: str) -> str:
    _, task_id = await _create_task(client, engagement_id)
    response = await client.post(
        f"/api/v1/tasks/{task_id}/http-actions",
        json={
            "action_type": "public_page_read",
            "target": "https://api.example.test/v1",
            "idempotency_key": "report-evidence-action",
        },
        headers=OPERATOR_HEADERS,
    )
    assert response.status_code == 201
    return str(response.json()["id"])


def _persist_evidence(database_path: Path, engagement_id: str, action_id: str) -> tuple[str, bytes]:
    evidence_id = new_evidence_id()
    raw = b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\r\n{\"ok\":true}"
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
    return str(evidence_id), raw


async def test_report_export_is_idempotent_audited_and_integrity_checked(
    tmp_path: Path,
) -> None:
    database_path = tmp_path / "report-export.db"
    async with authenticated_client(database_path) as client:
        client.headers.update(OPERATOR_HEADERS)
        engagement_id = await _create_engagement(client)
        missing_key = await client.post(
            f"/api/v1/engagements/{engagement_id}/report-exports",
            json={"format": "json"},
        )
        headers = {**OPERATOR_HEADERS, "Idempotency-Key": "final-report-v1"}
        created = await client.post(
            f"/api/v1/engagements/{engagement_id}/report-exports",
            json={"format": "json"},
            headers=headers,
        )
        replay = await client.post(
            f"/api/v1/engagements/{engagement_id}/report-exports",
            json={"format": "json"},
            headers=headers,
        )
        conflict = await client.post(
            f"/api/v1/engagements/{engagement_id}/report-exports",
            json={"format": "markdown"},
            headers=headers,
        )
        export_id = str(created.json()["id"])
        operator_download = await client.get(
            f"/api/v1/engagements/{engagement_id}/report-exports/{export_id}/download",
            headers=OPERATOR_HEADERS,
        )
        downloaded = await client.get(
            f"/api/v1/engagements/{engagement_id}/report-exports/{export_id}/download",
            headers=EVIDENCE_READER_HEADERS,
        )
        listed = await client.get(
            f"/api/v1/engagements/{engagement_id}/report-exports",
            headers=OPERATOR_HEADERS,
        )
        audit = await client.get(
            f"/api/v1/engagements/{engagement_id}/audit-events",
            headers=OPERATOR_HEADERS,
        )

    assert missing_key.status_code == 422
    assert created.status_code == 201
    assert replay.status_code == 200
    assert replay.json()["id"] == export_id
    assert conflict.status_code == 409
    assert operator_download.status_code == 401
    assert downloaded.status_code == 200
    assert downloaded.json()["engagement_id"] == engagement_id
    assert downloaded.headers["x-content-sha256"] == hashlib.sha256(downloaded.content).hexdigest()
    assert listed.json()["total"] == 1
    assert [item["event_type"] for item in audit.json()["items"][:2]] == [
        "report.export_downloaded",
        "report.export_created",
    ]


async def test_report_download_rejects_tampered_snapshot(tmp_path: Path) -> None:
    database_path = tmp_path / "tampered-report.db"
    async with authenticated_client(database_path) as client:
        client.headers.update(OPERATOR_HEADERS)
        engagement_id = await _create_engagement(client)
        created = await client.post(
            f"/api/v1/engagements/{engagement_id}/report-exports",
            json={"format": "markdown"},
            headers={**OPERATOR_HEADERS, "Idempotency-Key": "tamper-check"},
        )
        export_id = str(created.json()["id"])
        engine = create_engine(f"sqlite:///{database_path}", pool_pre_ping=False)
        try:
            with create_session_factory(engine).begin() as session:
                row = session.get(ReportExportRecord, export_id)
                assert row is not None
                row.content = b"tampered"
        finally:
            engine.dispose()
        downloaded = await client.get(
            f"/api/v1/engagements/{engagement_id}/report-exports/{export_id}/download",
            headers=EVIDENCE_READER_HEADERS,
        )

    assert downloaded.status_code == 409
    assert downloaded.json()["detail"] == "report_export_integrity_failed"


async def test_raw_evidence_requires_reader_and_records_access(tmp_path: Path) -> None:
    database_path = tmp_path / "raw-evidence.db"
    async with authenticated_client(database_path) as client:
        client.headers.update(OPERATOR_HEADERS)
        engagement_id = await _create_engagement(client)
        action_id = await _create_action(client, engagement_id)
        evidence_id, raw = _persist_evidence(database_path, engagement_id, action_id)
        path = f"/api/v1/engagements/{engagement_id}/evidence/{evidence_id}/raw"
        operator_attempt = await client.get(path, headers=OPERATOR_HEADERS)
        wrong_boundary = await client.get(
            f"/api/v1/engagements/00000000-0000-7000-8000-000000000999/evidence/{evidence_id}/raw",
            headers=EVIDENCE_READER_HEADERS,
        )
        downloaded = await client.get(path, headers=EVIDENCE_READER_HEADERS)
        audit = await client.get(
            f"/api/v1/engagements/{engagement_id}/audit-events",
            headers=OPERATOR_HEADERS,
        )

    assert operator_attempt.status_code == 401
    assert wrong_boundary.status_code == 404
    assert downloaded.status_code == 200
    assert downloaded.content == raw
    assert downloaded.headers["content-type"] == "application/http"
    assert downloaded.headers["x-content-sha256"] == hashlib.sha256(raw).hexdigest()
    assert audit.json()["items"][0]["event_type"] == "evidence.raw_accessed"
    assert audit.json()["items"][0]["actor"] == "evidence-reader@example.test"


async def test_raw_evidence_fails_closed_without_reader_or_with_tampering(
    tmp_path: Path,
) -> None:
    async with console_client(tmp_path / "not-ready.db") as client:
        unavailable = await client.get(
            "/api/v1/engagements/00000000-0000-7000-8000-000000000001/"
            "evidence/00000000-0000-7000-8000-000000000002/raw"
        )
    assert unavailable.status_code == 503
    assert unavailable.json()["detail"] == "evidence_access_not_ready"

    database_path = tmp_path / "tampered-evidence.db"
    async with authenticated_client(database_path) as client:
        client.headers.update(OPERATOR_HEADERS)
        engagement_id = await _create_engagement(client)
        action_id = await _create_action(client, engagement_id)
        evidence_id, _ = _persist_evidence(database_path, engagement_id, action_id)
        engine = create_engine(f"sqlite:///{database_path}", pool_pre_ping=False)
        try:
            with create_session_factory(engine).begin() as session:
                row = session.get(EvidencePayloadRecord, EvidenceId(evidence_id))
                assert row is not None
                row.raw_content = b"tampered"
        finally:
            engine.dispose()
        rejected = await client.get(
            f"/api/v1/engagements/{engagement_id}/evidence/{evidence_id}/raw",
            headers=EVIDENCE_READER_HEADERS,
        )

    assert rejected.status_code == 409
    assert rejected.json()["detail"] == "evidence_integrity_failed"
