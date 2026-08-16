"""Docker worker runtime tests using a fake CLI runner (no Docker required)."""

from __future__ import annotations

import sys
from collections.abc import Sequence
from datetime import UTC, datetime, timedelta

import pytest

from tests.execution.test_protocol import request
from vuln_proof_claw.config.models import DockerConfig
from vuln_proof_claw.domain.identifiers import EvidenceId
from vuln_proof_claw.execution.docker_runtime import (
    CommandResult,
    DockerWorkerRuntime,
    SubprocessDockerCommandRunner,
    build_worker_manager,
)
from vuln_proof_claw.execution.manager import (
    DisabledWorkerManager,
    LifecycleWorkerManager,
    WorkerExecutionUnavailableError,
    WorkerManagerError,
)
from vuln_proof_claw.execution.protocol import WorkerResponse, WorkerResultStatus

NOW = datetime(2026, 8, 16, 12, 0, tzinfo=UTC)


class FakeDockerCommandRunner:
    def __init__(self) -> None:
        self.calls: list[list[str]] = []
        self.results: dict[str, CommandResult] = {}

    def program(self, subcommand: str, result: CommandResult) -> None:
        self.results[subcommand] = result

    async def run(
        self,
        args: Sequence[str],
        *,
        timeout_seconds: float | None = None,
    ) -> CommandResult:
        del timeout_seconds
        self.calls.append(list(args))
        return self.results.get(args[0], CommandResult(0, "", ""))


def _enabled_config(**overrides: object) -> DockerConfig:
    values: dict[str, object] = {"runtime_enabled": True, "worker_image": "worker:test"}
    values.update(overrides)
    return DockerConfig(**values)


def _runtime(runner: FakeDockerCommandRunner, **overrides: object) -> DockerWorkerRuntime:
    return DockerWorkerRuntime(_enabled_config(**overrides), runner)


def _response_json() -> str:
    worker_request = request()
    return WorkerResponse(
        request_id=worker_request.request_id,
        engagement_id=worker_request.engagement_id,
        action_id=worker_request.action_id,
        status=WorkerResultStatus.SUCCEEDED,
        started_at=NOW,
        completed_at=NOW + timedelta(seconds=1),
        evidence_ids=(EvidenceId("00000000-0000-7000-8000-000000000004"),),
        exit_code=0,
    ).model_dump_json()


def test_disabled_runtime_and_manager_fail_closed() -> None:
    with pytest.raises(WorkerExecutionUnavailableError, match="disabled"):
        DockerWorkerRuntime(DockerConfig(), FakeDockerCommandRunner())
    assert isinstance(build_worker_manager(DockerConfig()), DisabledWorkerManager)


def test_enabled_manager_is_a_lifecycle_manager_with_image_identity() -> None:
    manager = build_worker_manager(_enabled_config())
    assert isinstance(manager, LifecycleWorkerManager)
    assert manager.runtime_identity == "docker:worker:test"


async def test_create_applies_every_hardening_flag() -> None:
    runner = FakeDockerCommandRunner()
    runner.program("create", CommandResult(0, "container-abc\n", ""))
    runtime = _runtime(runner, worker_network="isolated-net")

    reference = await runtime.create(request())

    assert reference == "container-abc"
    args = runner.calls[0]
    assert args[0] == "create"
    assert args[-1] == "worker:test"
    assert args[1:3] == ["--network", "isolated-net"]
    assert "--cap-drop" in args
    assert args[args.index("--cap-drop") + 1] == "ALL"
    assert "--read-only" in args
    assert args[args.index("--security-opt") + 1] == "no-new-privileges"
    assert "--pids-limit" in args
    assert "--memory" in args
    assert "--cpus" in args
    label = args[args.index("--label") + 1]
    assert label == "com.vuln-proof-claw.owned=true"
    env = args[args.index("--env") + 1]
    assert env.startswith("VULN_PROOF_CLAW_WORKER_REQUEST={")


async def test_create_failure_and_empty_reference_raise() -> None:
    failing = FakeDockerCommandRunner()
    failing.program("create", CommandResult(1, "", "boom"))
    with pytest.raises(WorkerManagerError, match="docker_create_failed"):
        await _runtime(failing).create(request())

    empty = FakeDockerCommandRunner()
    empty.program("create", CommandResult(0, "   \n", ""))
    with pytest.raises(WorkerManagerError, match="empty_reference"):
        await _runtime(empty).create(request())


async def test_wait_parses_terminal_worker_response() -> None:
    runner = FakeDockerCommandRunner()
    runner.program("wait", CommandResult(0, "0\n", ""))
    runner.program("logs", CommandResult(0, _response_json(), ""))

    response = await _runtime(runner).wait("container-abc")

    assert response.status is WorkerResultStatus.SUCCEEDED
    assert ["wait", "container-abc"] in runner.calls
    assert ["logs", "container-abc"] in runner.calls


async def test_wait_selects_response_after_a_summary_line() -> None:
    runner = FakeDockerCommandRunner()
    summary = '{"capture_schema":"worker-capture-v1","status":"succeeded"}'
    runner.program("logs", CommandResult(0, f"{summary}\n{_response_json()}\n", ""))

    response = await _runtime(runner).wait("container-abc")

    assert response.status is WorkerResultStatus.SUCCEEDED


async def test_wait_rejects_unparseable_or_missing_logs() -> None:
    invalid = FakeDockerCommandRunner()
    invalid.program("logs", CommandResult(0, "not-json", ""))
    with pytest.raises(WorkerManagerError, match="worker_response_invalid"):
        await _runtime(invalid).wait("container-abc")

    log_failure = FakeDockerCommandRunner()
    log_failure.program("logs", CommandResult(1, "", "gone"))
    with pytest.raises(WorkerManagerError, match="docker_logs_failed"):
        await _runtime(log_failure).wait("container-abc")


async def test_start_cancel_destroy_issue_expected_commands() -> None:
    runner = FakeDockerCommandRunner()
    runtime = _runtime(runner)

    await runtime.start("c1")
    await runtime.cancel("c1")
    await runtime.destroy("c1")

    assert ["start", "c1"] in runner.calls
    assert ["stop", "--time", "5", "c1"] in runner.calls
    assert ["rm", "--force", "--volumes", "c1"] in runner.calls


async def test_lifecycle_command_failures_raise_safe_errors() -> None:
    runner = FakeDockerCommandRunner()
    runner.program("start", CommandResult(1, "", ""))
    runner.program("stop", CommandResult(2, "", ""))
    runner.program("rm", CommandResult(3, "", ""))
    runtime = _runtime(runner)

    with pytest.raises(WorkerManagerError, match="docker_start_failed"):
        await runtime.start("c1")
    with pytest.raises(WorkerManagerError, match="docker_stop_failed"):
        await runtime.cancel("c1")
    with pytest.raises(WorkerManagerError, match="docker_remove_failed"):
        await runtime.destroy("c1")


async def test_list_owned_filters_by_label_and_parses_ids() -> None:
    runner = FakeDockerCommandRunner()
    runner.program("ps", CommandResult(0, "id-1\nid-2\n\n", ""))
    ids = await _runtime(runner).list_owned()

    assert ids == ("id-1", "id-2")
    ps_call = next(call for call in runner.calls if call[0] == "ps")
    assert "--all" in ps_call
    assert "--quiet" in ps_call
    assert ps_call[ps_call.index("--filter") + 1] == "label=com.vuln-proof-claw.owned=true"


async def test_list_owned_failure_raises() -> None:
    runner = FakeDockerCommandRunner()
    runner.program("ps", CommandResult(1, "", "docker daemon down"))
    with pytest.raises(WorkerManagerError, match="docker_list_failed"):
        await _runtime(runner).list_owned()


async def test_subprocess_runner_captures_output() -> None:
    runner = SubprocessDockerCommandRunner(sys.executable)
    result = await runner.run(["-c", "import sys; sys.stdout.write('ok'); sys.exit(3)"])
    assert result.returncode == 3
    assert result.stdout == "ok"


async def test_subprocess_runner_kills_on_timeout() -> None:
    runner = SubprocessDockerCommandRunner(sys.executable)
    with pytest.raises(TimeoutError):
        await runner.run(["-c", "import time; time.sleep(30)"], timeout_seconds=0.5)
