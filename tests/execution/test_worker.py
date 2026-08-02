"""Tests for the fail-closed restricted Worker process boundary."""

from __future__ import annotations

import io
import json
from datetime import UTC, datetime

import pytest

from vuln_proof_claw.domain.enums import RiskLevel
from vuln_proof_claw.domain.identifiers import ActionId, EngagementId
from vuln_proof_claw.execution.protocol import (
    WorkerLimits,
    WorkerRequest,
    WorkerResponse,
    WorkerResultStatus,
    WorkerScope,
)
from vuln_proof_claw.execution.worker import (
    MAXIMUM_REQUEST_BYTES,
    WORKER_DISABLED_EXIT_CODE,
    evaluate_request,
    run,
)

NOW = datetime(2026, 8, 2, 12, 0, tzinfo=UTC)


def request() -> WorkerRequest:
    return WorkerRequest(
        request_id="worker-e2e-1",
        engagement_id=EngagementId("00000000-0000-7000-8000-000000000001"),
        action_id=ActionId("00000000-0000-7000-8000-000000000002"),
        action_type="passive_http_probe",
        normalized_target="https://example.test:443/",
        parameter_digest="a" * 64,
        risk_level=RiskLevel.L1,
        idempotency_key="worker-e2e-1",
        capabilities=("http_client",),
        scope=WorkerScope(
            allowed_hostnames=("example.test",),
            allowed_ports=(443,),
            allowed_schemes=("https",),
        ),
        limits=WorkerLimits(
            timeout_seconds=30,
            memory_megabytes=128,
            cpu_count=0.5,
            process_limit=32,
        ),
    )


def test_valid_request_returns_bound_policy_denial_without_evidence() -> None:
    original = request()

    response = evaluate_request(original.model_dump_json().encode(), clock=lambda: NOW)

    assert response == WorkerResponse(
        request_id=original.request_id,
        engagement_id=original.engagement_id,
        action_id=original.action_id,
        status=WorkerResultStatus.POLICY_DENIED,
        started_at=NOW,
        completed_at=NOW,
        exit_code=WORKER_DISABLED_EXIT_CODE,
        error_code="worker_execution_not_implemented",
    )
    assert response.evidence_ids == ()
    assert response.artifact_ids == ()


def test_run_emits_one_strict_worker_response() -> None:
    output = io.StringIO()

    exit_code = run(
        io.BytesIO(request().model_dump_json().encode()),
        output,
        clock=lambda: NOW,
    )

    assert exit_code == WORKER_DISABLED_EXIT_CODE
    assert output.getvalue().count("\n") == 1
    response = WorkerResponse.model_validate_json(output.getvalue())
    assert response.request_id == "worker-e2e-1"
    assert response.status is WorkerResultStatus.POLICY_DENIED


@pytest.mark.parametrize(
    "payload",
    [
        b"",
        b"not-json",
        b'{"request_id":"secret-target.example"}',
        b"x" * (MAXIMUM_REQUEST_BYTES + 1),
    ],
    ids=("empty", "malformed", "invalid-schema", "oversized"),
)
def test_invalid_or_oversized_input_is_not_reflected(payload: bytes) -> None:
    output = io.StringIO()

    exit_code = run(io.BytesIO(payload), output, clock=lambda: NOW)

    assert exit_code == WORKER_DISABLED_EXIT_CODE
    assert json.loads(output.getvalue()) == {
        "component": "worker",
        "error_code": "worker_request_invalid",
        "state": "rejected",
    }
    assert "secret-target" not in output.getvalue()
