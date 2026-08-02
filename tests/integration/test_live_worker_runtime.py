"""Explicitly enabled live Docker Worker protocol verification."""

from __future__ import annotations

import os
import sys

import pytest

from vuln_proof_claw.config.models import DockerEngineBackendConfig
from vuln_proof_claw.domain.enums import RiskLevel
from vuln_proof_claw.domain.identifiers import ActionId, EngagementId, WorkerId
from vuln_proof_claw.engine.docker_backend import DockerEngineBackend
from vuln_proof_claw.execution.docker_runtime import DockerWorkerRuntime, RestrictedRuntimePolicy
from vuln_proof_claw.execution.protocol import (
    WorkerLimits,
    WorkerRequest,
    WorkerResultStatus,
    WorkerScope,
)


def live_request() -> WorkerRequest:
    return WorkerRequest(
        request_id="live-worker-boundary-1",
        engagement_id=EngagementId("00000000-0000-7000-8000-000000000011"),
        action_id=ActionId("00000000-0000-7000-8000-000000000012"),
        action_type="passive_http_probe",
        normalized_target="https://example.test:443/",
        parameter_digest="a" * 64,
        risk_level=RiskLevel.L1,
        idempotency_key="live-worker-boundary-1",
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


@pytest.mark.skipif(sys.platform != "linux", reason="live Docker test requires a Unix socket")
async def test_live_digest_pinned_worker_round_trip_when_explicitly_enabled() -> None:
    if os.getenv("VULN_PROOF_CLAW_RUN_WORKER_INTEGRATION") != "1":
        pytest.skip("live Worker integration is not enabled")

    image = os.environ["VULN_PROOF_CLAW_TEST_WORKER_IMAGE"]
    network = os.getenv("VULN_PROOF_CLAW_TEST_WORKER_NETWORK", "vuln-proof-claw-workers")
    socket_path = os.getenv("VULN_PROOF_CLAW_TEST_DOCKER_SOCKET", "/var/run/docker.sock")
    config = DockerEngineBackendConfig(
        enabled=True,
        socket_path=socket_path,
        allowed_image=image,
        allowed_network=network,
    )
    policy = RestrictedRuntimePolicy(image=image, network=network)
    reference: str | None = None

    async with DockerEngineBackend(config) as engine:
        await engine.check_ready()
        runtime = DockerWorkerRuntime(engine, policy)
        try:
            reference = await runtime.create(
                live_request(),
                worker_id=WorkerId("00000000-0000-7000-8000-000000000099"),
            )
            await runtime.start(reference)
            response = await runtime.wait(reference)
        finally:
            if reference is not None:
                await runtime.destroy(reference)

    assert response.status is WorkerResultStatus.POLICY_DENIED
    assert response.error_code == "worker_execution_not_implemented"
    assert response.exit_code == 2
    assert response.evidence_ids == ()
