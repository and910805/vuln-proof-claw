"""Live Docker integration checks for the concrete worker runtime.

These tests are skipped unless a Docker daemon is reachable and the operator
opts in with ``VULN_PROOF_CLAW_DOCKER_INTEGRATION=1``. They never contact the
public internet: a disposable target is placed on an ``--internal`` network and
the only reachability that succeeds is to that local target.

Run manually with, for example::

    VULN_PROOF_CLAW_DOCKER_INTEGRATION=1 pytest tests/execution/test_docker_runtime_integration.py
"""

from __future__ import annotations

import os
import shutil
from collections.abc import AsyncIterator

import pytest

from tests.execution.test_protocol import request
from vuln_proof_claw.config.models import DockerConfig
from vuln_proof_claw.domain.enums import RiskLevel
from vuln_proof_claw.domain.identifiers import ActionId, EngagementId
from vuln_proof_claw.execution.docker_runtime import (
    DockerWorkerRuntime,
    SubprocessDockerCommandRunner,
)
from vuln_proof_claw.execution.protocol import (
    WorkerLimits,
    WorkerRequest,
    WorkerResponse,
    WorkerResultStatus,
    WorkerScope,
)

_WORKER_IMAGE = "vuln-proof-claw-worker:dev"

_OPT_IN = os.getenv("VULN_PROOF_CLAW_DOCKER_INTEGRATION") == "1"
_TARGET_IMAGE = "busybox"
_CLIENT_IMAGE = "curlimages/curl:8.10.1"
_SUFFIX = str(os.getpid())

pytestmark = pytest.mark.skipif(
    not (_OPT_IN and shutil.which("docker")),
    reason="Docker integration is not enabled",
)


@pytest.fixture
def runner() -> SubprocessDockerCommandRunner:
    return SubprocessDockerCommandRunner()


@pytest.fixture
async def internal_network(runner: SubprocessDockerCommandRunner) -> AsyncIterator[str]:
    name = f"vpc-int-{_SUFFIX}"
    await runner.run(["network", "rm", "--force", name])
    result = await runner.run(["network", "create", "--internal", name])
    assert result.returncode == 0, result.stderr
    try:
        yield name
    finally:
        await runner.run(["network", "rm", "--force", name])


async def test_internal_network_blocks_egress_but_reaches_local_target(
    runner: SubprocessDockerCommandRunner,
    internal_network: str,
) -> None:
    target = f"vpc-target-{_SUFFIX}"
    listen = (
        "while true; do printf 'HTTP/1.1 200 OK\\r\\n"
        "Content-Length: 2\\r\\n\\r\\nhi' | nc -l -p 8080; done"
    )
    started = await runner.run(
        [
            "run", "-d", "--rm",
            "--name", target,
            "--network", internal_network,
            _TARGET_IMAGE, "sh", "-c", listen,
        ]
    )
    assert started.returncode == 0, started.stderr
    try:
        reachable = await runner.run(
            [
                "run", "--rm", "--network", internal_network,
                "--cap-drop", "ALL", "--security-opt", "no-new-privileges",
                _CLIENT_IMAGE, "--max-time", "5", "-s", f"http://{target}:8080",
            ]
        )
        assert reachable.returncode == 0, reachable.stderr
        assert "hi" in reachable.stdout

        egress = await runner.run(
            [
                "run", "--rm", "--network", internal_network,
                "--cap-drop", "ALL", "--security-opt", "no-new-privileges",
                _CLIENT_IMAGE, "--max-time", "5", "-s", "http://1.1.1.1",
            ]
        )
        assert egress.returncode != 0
    finally:
        await runner.run(["rm", "--force", target])


@pytest.fixture
def reaping_config(internal_network: str) -> DockerConfig:
    return DockerConfig(
        runtime_enabled=True,
        worker_image=_CLIENT_IMAGE,
        worker_network=internal_network,
        ownership_label=f"com.vuln-proof-claw.itest-{_SUFFIX}",
    )


async def test_created_container_is_hardened_listed_and_reaped(
    runner: SubprocessDockerCommandRunner,
    reaping_config: DockerConfig,
) -> None:
    runtime = DockerWorkerRuntime(reaping_config, runner)
    reference = await runtime.create(request())
    try:
        inspect = await runner.run(
            [
                "inspect",
                "--format",
                "{{.HostConfig.ReadonlyRootfs}} {{.HostConfig.CapDrop}}",
                reference,
            ]
        )
        assert inspect.returncode == 0, inspect.stderr
        assert inspect.stdout.strip().startswith("true")
        assert "ALL" in inspect.stdout

        owned = await runtime.list_owned()
        assert any(reference.startswith(short) for short in owned)
    finally:
        await runtime.destroy(reference)

    remaining = await runtime.list_owned()
    assert not any(reference.startswith(short) for short in remaining)


def _worker_request(target_url: str, host: str, port: int, scheme: str) -> WorkerRequest:
    return WorkerRequest(
        request_id="itest-1",
        engagement_id=EngagementId("00000000-0000-7000-8000-000000000001"),
        action_id=ActionId("00000000-0000-7000-8000-000000000002"),
        action_type="public_page_read",
        normalized_target=target_url,
        parameter_digest="a" * 64,
        risk_level=RiskLevel.L0,
        idempotency_key="itest-1",
        capabilities=("http_client",),
        scope=WorkerScope(
            allowed_hostnames=(host,),
            allowed_ports=(port,),
            allowed_schemes=(scheme,),
            allowed_paths=("/",),
        ),
        limits=WorkerLimits(
            timeout_seconds=8,
            memory_megabytes=256,
            cpu_count=1.0,
            process_limit=64,
        ),
    )


async def test_real_worker_captures_local_target_but_not_the_internet(
    runner: SubprocessDockerCommandRunner,
    internal_network: str,
) -> None:
    image_present = await runner.run(["image", "inspect", _WORKER_IMAGE])
    if image_present.returncode != 0:
        pytest.skip(f"{_WORKER_IMAGE} is not built")

    host = f"target-{_SUFFIX}"
    page = (
        "mkdir -p /www && printf '<html>hi</html>' > /www/index.html "
        "&& httpd -f -p 8080 -h /www"
    )
    started = await runner.run(
        ["run", "-d", "--rm", "--name", host, "--network", internal_network,
         _TARGET_IMAGE, "sh", "-c", page]
    )
    assert started.returncode == 0, started.stderr

    config = DockerConfig(
        runtime_enabled=True,
        worker_image=_WORKER_IMAGE,
        worker_network=internal_network,
        ownership_label=f"com.vuln-proof-claw.worker-itest-{_SUFFIX}",
    )
    runtime = DockerWorkerRuntime(config, runner)
    try:
        local = await _run(runtime, _worker_request(f"http://{host}:8080/", host, 8080, "http"))
        assert local.status is WorkerResultStatus.SUCCEEDED
        assert len(local.evidence_ids) == 1

        internet = await _run(
            runtime, _worker_request("http://example.com:80/", "example.com", 80, "http")
        )
        assert internet.status is WorkerResultStatus.FAILED
        assert internet.error_code == "transport_failure"
    finally:
        await runner.run(["rm", "--force", host])


async def _run(runtime: DockerWorkerRuntime, worker_request: WorkerRequest) -> WorkerResponse:
    reference = await runtime.create(worker_request)
    try:
        await runtime.start(reference)
        return await runtime.wait(reference)
    finally:
        await runtime.destroy(reference)
