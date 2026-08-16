"""Tests for the strict v1 worker protocol and disabled manager."""

from __future__ import annotations

import json
from datetime import UTC, datetime, timedelta

import pytest
from pydantic import ValidationError

from vuln_proof_claw.domain.enums import RiskLevel
from vuln_proof_claw.domain.identifiers import (
    ActionId,
    ApprovalId,
    EngagementId,
    EvidenceId,
)
from vuln_proof_claw.execution.manager import (
    DisabledWorkerManager,
    WorkerExecutionUnavailableError,
)
from vuln_proof_claw.execution.protocol import (
    WorkerLimits,
    WorkerRequest,
    WorkerResponse,
    WorkerResultStatus,
    WorkerScope,
)
from vuln_proof_claw.execution.worker import main as worker_main

NOW = datetime(2026, 7, 31, 10, 0, tzinfo=UTC)
DIGEST = "a" * 64


def worker_scope() -> WorkerScope:
    return WorkerScope(
        allowed_hostnames=("EXAMPLE.test.",),
        allowed_cidrs=(),
        allowed_ports=(443,),
        allowed_schemes=("https",),
        allowed_paths=("/api",),
        denied_hostnames=("blocked.example.test",),
        denied_cidrs=("192.0.2.128/25",),
        denied_paths=("/api/admin",),
    )


def worker_limits() -> WorkerLimits:
    return WorkerLimits(
        timeout_seconds=300,
        memory_megabytes=512,
        cpu_count=1.0,
        process_limit=128,
    )


def request(*, risk_level: RiskLevel = RiskLevel.L2) -> WorkerRequest:
    return WorkerRequest(
        request_id="request-1",
        engagement_id=EngagementId("00000000-0000-7000-8000-000000000001"),
        action_id=ActionId("00000000-0000-7000-8000-000000000002"),
        action_type="file_upload",
        normalized_target="https://example.test:443/api/upload",
        parameter_digest=DIGEST,
        risk_level=risk_level,
        approval_id=(
            ApprovalId("00000000-0000-7000-8000-000000000003")
            if risk_level.requires_approval
            else None
        ),
        idempotency_key="action-1",
        capabilities=("http_client",),
        scope=worker_scope(),
        limits=worker_limits(),
    )


def test_request_round_trip_is_strict_and_versioned() -> None:
    original = request()

    restored = WorkerRequest.model_validate_json(original.model_dump_json())

    assert restored == original
    assert restored.protocol_version == "v1"
    assert restored.scope.allowed_hostnames == ("example.test",)
    assert restored.scope.denied_cidrs == ("192.0.2.128/25",)
    assert "provider_api_key" not in original.model_dump()


def test_unknown_top_level_credentials_are_rejected() -> None:
    payload = request().model_dump(mode="json")
    payload["provider_api_key"] = "must-not-cross-worker-boundary"

    with pytest.raises(ValidationError, match="Extra inputs"):
        WorkerRequest.model_validate(payload)


def test_l2_to_l4_requests_require_approval() -> None:
    payload = request().model_dump()
    payload["approval_id"] = None

    with pytest.raises(ValidationError, match="approval_id"):
        WorkerRequest.model_validate(payload)


@pytest.mark.parametrize(
    ("target", "message"),
    [
        ("https://EXAMPLE.test/api/upload", "canonical"),
        ("https://outside.test:443/api/upload", "outside"),
        ("https://example.test:443/api/admin", "outside"),
    ],
)
def test_request_target_must_be_canonical_and_inside_worker_scope(
    target: str,
    message: str,
) -> None:
    payload = request().model_dump()
    payload["normalized_target"] = target

    with pytest.raises(ValidationError, match=message):
        WorkerRequest.model_validate(payload)


def test_response_requires_safe_error_code_and_ordered_aware_times() -> None:
    success = WorkerResponse(
        request_id="request-1",
        engagement_id=request().engagement_id,
        action_id=request().action_id,
        status=WorkerResultStatus.SUCCEEDED,
        started_at=NOW,
        completed_at=NOW + timedelta(seconds=1),
        evidence_ids=(EvidenceId("00000000-0000-7000-8000-000000000004"),),
        exit_code=0,
    )
    assert success.protocol_version == "v1"

    with pytest.raises(ValidationError, match="evidence_id"):
        WorkerResponse(
            request_id="request-1",
            engagement_id=request().engagement_id,
            action_id=request().action_id,
            status=WorkerResultStatus.SUCCEEDED,
            started_at=NOW,
            completed_at=NOW,
        )

    with pytest.raises(ValidationError, match="error_code"):
        WorkerResponse(
            request_id="request-1",
            engagement_id=request().engagement_id,
            action_id=request().action_id,
            status=WorkerResultStatus.FAILED,
            started_at=NOW,
            completed_at=NOW,
        )

    with pytest.raises(ValidationError, match="earlier"):
        WorkerResponse(
            request_id="request-1",
            engagement_id=request().engagement_id,
            action_id=request().action_id,
            status=WorkerResultStatus.FAILED,
            started_at=NOW,
            completed_at=NOW - timedelta(seconds=1),
            error_code="worker_failed",
        )


async def test_disabled_manager_fails_closed() -> None:
    manager = DisabledWorkerManager()

    with pytest.raises(WorkerExecutionUnavailableError, match="not configured"):
        await manager.submit(request())

    with pytest.raises(WorkerExecutionUnavailableError, match="not configured"):
        await manager.start("missing")

    assert await manager.status("missing") is None
    assert await manager.collect("missing") is None


def test_worker_entry_point_without_request_fails_safely(
    capsys: pytest.CaptureFixture[str],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.delenv("VULN_PROOF_CLAW_WORKER_REQUEST", raising=False)

    with pytest.raises(SystemExit, match="2"):
        worker_main()

    payload = json.loads(capsys.readouterr().out)
    assert payload["status"] == "worker_error"
    assert "target" not in payload
    assert "credential" not in payload
