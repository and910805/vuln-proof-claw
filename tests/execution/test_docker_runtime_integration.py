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
from vuln_proof_claw.execution.docker_runtime import (
    DockerWorkerRuntime,
    SubprocessDockerCommandRunner,
)

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
