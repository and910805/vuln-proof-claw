"""Restricted Docker runtime tests over a non-privileged in-memory engine."""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import fields
from datetime import datetime

import pytest

from tests.execution.test_protocol import NOW, request
from vuln_proof_claw.config.models import DockerConfig
from vuln_proof_claw.domain.identifiers import EvidenceId, WorkerId
from vuln_proof_claw.execution.docker_runtime import (
    ContainerWaitResult,
    DockerRuntimeError,
    DockerWorkerRuntime,
    OwnedContainer,
    RestrictedContainerSpec,
    RestrictedRuntimePolicy,
    restricted_policy_from_config,
)
from vuln_proof_claw.execution.manager import LifecycleWorkerManager
from vuln_proof_claw.execution.protocol import WorkerLimits, WorkerRequest, WorkerResponse

IMAGE = f"ghcr.io/and910805/vuln-proof-claw-worker@sha256:{'a' * 64}"
WORKER_ID = WorkerId("00000000-0000-7000-8000-000000000099")
REFERENCE = "private-container-reference"


def policy(**changes: object) -> RestrictedRuntimePolicy:
    values: dict[str, object] = {
        "image": IMAGE,
        "network": "vuln-proof-claw-workers",
    }
    values.update(changes)
    return RestrictedRuntimePolicy(**values)  # type: ignore[arg-type]


def successful_response(worker_request: WorkerRequest | None = None) -> WorkerResponse:
    value = worker_request or request()
    return WorkerResponse(
        request_id=value.request_id,
        engagement_id=value.engagement_id,
        action_id=value.action_id,
        status="succeeded",
        started_at=NOW,
        completed_at=NOW,
        evidence_ids=(EvidenceId("00000000-0000-7000-8000-000000000004"),),
        exit_code=0,
    )


class MemoryDockerEngine:
    def __init__(self) -> None:
        self.spec: RestrictedContainerSpec | None = None
        self.calls: list[str] = []
        self.wait_limit: int | None = None
        self.wait_result = ContainerWaitResult(
            exit_code=0,
            output=successful_response().model_dump_json().encode(),
        )
        self.containers: tuple[OwnedContainer, ...] = ()
        self.failure: dict[str, Exception] = {}

    async def create(self, spec: RestrictedContainerSpec) -> str:
        self.calls.append("create")
        self.spec = spec
        self._fail("create")
        return REFERENCE

    async def start(self, reference: str) -> None:
        assert reference == REFERENCE
        self.calls.append("start")
        self._fail("start")

    async def wait(self, reference: str, *, maximum_output_bytes: int) -> ContainerWaitResult:
        assert reference == REFERENCE
        self.calls.append("wait")
        self.wait_limit = maximum_output_bytes
        self._fail("wait")
        return self.wait_result

    async def stop(self, reference: str, *, grace_seconds: int) -> None:
        assert reference == REFERENCE
        assert grace_seconds == 5
        self.calls.append("stop")
        self._fail("stop")

    async def remove(self, reference: str, *, force: bool, volumes: bool) -> None:
        assert reference == REFERENCE
        assert force
        assert volumes
        self.calls.append("remove")
        self._fail("remove")

    async def list_owned(self, *, labels: Mapping[str, str]) -> tuple[OwnedContainer, ...]:
        assert labels["io.vuln-proof-claw.managed-by"] == "worker-runtime"
        assert labels["io.vuln-proof-claw.runtime-identity"].startswith("docker:")
        self.calls.append("list")
        self._fail("list")
        return self.containers

    def _fail(self, operation: str) -> None:
        if error := self.failure.get(operation):
            raise error


async def test_create_emits_only_the_complete_hardened_container_spec() -> None:
    engine = MemoryDockerEngine()
    runtime = DockerWorkerRuntime(engine, policy(), clock=lambda: NOW)
    worker_request = request()

    reference = await runtime.create(worker_request, worker_id=WORKER_ID)

    assert reference == REFERENCE
    assert engine.spec is not None
    spec = engine.spec
    assert spec.name == f"vpc-worker-{WORKER_ID}"
    assert spec.image == IMAGE
    assert spec.network == "vuln-proof-claw-workers"
    assert spec.user == "10002:10002"
    assert spec.read_only_root
    assert spec.capability_drop == ("ALL",)
    assert spec.no_new_privileges
    assert spec.init
    assert spec.timeout_seconds == 300
    assert spec.memory_bytes == 512 * 1024 * 1024
    assert spec.nano_cpus == 1_000_000_000
    assert spec.process_limit == 128
    assert {path for path, _ in spec.tmpfs} == {
        "/tmp",  # noqa: S108 - asserts an isolated container tmpfs
        "/work",
    }
    assert all("noexec" in options and "nosuid" in options for _, options in spec.tmpfs)
    assert WorkerRequest.model_validate_json(spec.request_payload) == worker_request
    assert spec.label_map["io.vuln-proof-claw.worker-id"] == WORKER_ID
    assert spec.label_map["io.vuln-proof-claw.request-id"] == worker_request.request_id
    assert REFERENCE not in repr(spec)


async def test_runtime_completes_start_wait_cancel_destroy_and_inventory() -> None:
    engine = MemoryDockerEngine()
    runtime = DockerWorkerRuntime(engine, policy(), clock=lambda: NOW)
    await runtime.create(request(), worker_id=WORKER_ID)
    assert engine.spec is not None
    engine.containers = (
        OwnedContainer(
            reference=REFERENCE,
            labels=engine.spec.labels,
        ),
    )

    await runtime.start(REFERENCE)
    response = await runtime.wait(REFERENCE)
    resources = await runtime.list_resources()
    await runtime.cancel(REFERENCE)
    await runtime.destroy(REFERENCE)

    assert response == successful_response()
    assert engine.wait_limit == 1024 * 1024
    assert len(resources) == 1
    assert resources[0].worker_id == WORKER_ID
    assert resources[0].request_id == request().request_id
    assert resources[0].created_at == NOW
    assert REFERENCE not in repr(resources)
    assert engine.calls == ["create", "start", "wait", "list", "stop", "remove"]


async def test_lifecycle_manager_integrates_with_restricted_runtime() -> None:
    engine = MemoryDockerEngine()
    runtime = DockerWorkerRuntime(engine, policy(), clock=lambda: NOW)
    manager = LifecycleWorkerManager(runtime, clock=lambda: NOW)

    submitted = await manager.submit(request())
    started = await manager.start(submitted.worker_id)
    response = await manager.collect(submitted.worker_id)
    terminal = await manager.status(submitted.worker_id)

    assert engine.spec is not None
    assert engine.spec.label_map["io.vuln-proof-claw.worker-id"] == submitted.worker_id
    assert started.state.value == "running"
    assert response == successful_response()
    assert terminal is not None
    assert terminal.cleaned_up
    assert engine.calls == ["create", "start", "wait", "remove"]


@pytest.mark.parametrize(
    ("changes", "message"),
    [
        ({"image": "vuln-proof-claw-worker:latest"}, "sha256 digest"),
        ({"image": f"worker;touch-pwned@sha256:{'a' * 64}"}, "sha256 digest"),
        ({"image": f"worker@sha256:{'A' * 64}"}, "sha256 digest"),
        ({"network": "host"}, "dedicated and isolated"),
        ({"network": "control-plane"}, "dedicated and isolated"),
        ({"network": "bad network"}, "network name"),
        ({"user": "0:0"}, "non-root"),
        ({"user": "10002\n:10002"}, "non-root"),
        ({"maximum_output_bytes": 0}, "positive"),
        ({"maximum_cpu_count": float("inf")}, "positive"),
        ({"maximum_memory_megabytes": 32_769}, "hard ceiling"),
    ],
)
def test_policy_rejects_unpinned_or_unsafe_configuration(
    changes: dict[str, object],
    message: str,
) -> None:
    with pytest.raises(ValueError, match=message):
        policy(**changes)


def test_runtime_identity_changes_with_security_policy() -> None:
    original = policy()
    same = policy()
    changed = policy(maximum_output_bytes=512)

    assert original.identity == same.identity
    assert original.identity != changed.identity
    assert original.identity.startswith(f"docker:{IMAGE}#policy-sha256:")


async def test_custom_non_root_identity_owns_its_tmpfs() -> None:
    engine = MemoryDockerEngine()
    runtime = DockerWorkerRuntime(engine, policy(user="20000:20001"), clock=lambda: NOW)

    await runtime.create(request(), worker_id=WORKER_ID)

    assert engine.spec is not None
    assert engine.spec.user == "20000:20001"
    assert all("uid=20000" in options for _, options in engine.spec.tmpfs)
    assert all("gid=20001" in options for _, options in engine.spec.tmpfs)


def test_config_factory_requires_explicit_enablement_and_digest_pin() -> None:
    with pytest.raises(DockerRuntimeError, match="docker_runtime_disabled"):
        restricted_policy_from_config(DockerConfig())

    with pytest.raises(DockerRuntimeError, match="docker_runtime_policy_invalid"):
        restricted_policy_from_config(DockerConfig(runtime_enabled=True))

    configured = restricted_policy_from_config(
        DockerConfig(runtime_enabled=True, worker_image=IMAGE)
    )
    assert configured.image == IMAGE
    assert configured.network == "vuln-proof-claw-workers"


@pytest.mark.parametrize(
    "worker_request",
    [
        request().model_copy(update={"capabilities": ("shell",)}),
        request().model_copy(
            update={
                "limits": WorkerLimits(
                    timeout_seconds=2_000,
                    memory_megabytes=512,
                    cpu_count=1,
                    process_limit=128,
                )
            }
        ),
        request().model_copy(
            update={
                "limits": WorkerLimits(
                    timeout_seconds=300,
                    memory_megabytes=2_049,
                    cpu_count=1,
                    process_limit=128,
                )
            }
        ),
    ],
)
async def test_request_must_fit_runtime_capability_and_resource_policy(
    worker_request: WorkerRequest,
) -> None:
    engine = MemoryDockerEngine()
    runtime = DockerWorkerRuntime(engine, policy(), clock=lambda: NOW)

    with pytest.raises(DockerRuntimeError, match=r"not_allowed|limit_exceeded"):
        await runtime.create(worker_request, worker_id=WORKER_ID)
    assert engine.calls == []


async def test_request_size_and_clock_are_validated_before_engine_access() -> None:
    engine = MemoryDockerEngine()
    too_small = DockerWorkerRuntime(
        engine,
        policy(maximum_request_bytes=10),
        clock=lambda: NOW,
    )
    with pytest.raises(DockerRuntimeError, match="worker_request_limit_exceeded"):
        await too_small.create(request(), worker_id=WORKER_ID)

    naive_clock = DockerWorkerRuntime(
        engine,
        policy(),
        clock=lambda: datetime(2026, 8, 2),
    )
    with pytest.raises(DockerRuntimeError, match="timezone_aware"):
        await naive_clock.create(request(), worker_id=WORKER_ID)
    assert engine.calls == []


async def test_worker_and_request_identifiers_must_be_safe_container_metadata() -> None:
    engine = MemoryDockerEngine()
    runtime = DockerWorkerRuntime(engine, policy(), clock=lambda: NOW)
    with pytest.raises(DockerRuntimeError, match="worker_request_id_invalid"):
        await runtime.create(
            request().model_copy(update={"request_id": "request\nforged-label"}),
            worker_id=WORKER_ID,
        )
    with pytest.raises(DockerRuntimeError, match="worker_id_invalid"):
        await runtime.create(request(), worker_id=WorkerId("../../unsafe"))
    assert engine.calls == []


async def test_wait_rejects_oversized_or_invalid_protocol_output() -> None:
    engine = MemoryDockerEngine()
    runtime = DockerWorkerRuntime(engine, policy(maximum_output_bytes=32), clock=lambda: NOW)
    engine.wait_result = ContainerWaitResult(exit_code=1, output=b"x" * 33)
    with pytest.raises(DockerRuntimeError, match="worker_output_limit_exceeded"):
        await runtime.wait(REFERENCE)

    engine.wait_result = ContainerWaitResult(exit_code=1, output=b'{"secret":"value"}')
    with pytest.raises(DockerRuntimeError, match="worker_response_invalid") as captured:
        await runtime.wait(REFERENCE)
    assert "secret" not in str(captured.value)

    engine.wait_result = ContainerWaitResult(
        exit_code=9,
        output=successful_response().model_dump_json().encode(),
    )
    with pytest.raises(DockerRuntimeError, match="worker_exit_code_mismatch"):
        await DockerWorkerRuntime(engine, policy(), clock=lambda: NOW).wait(REFERENCE)


@pytest.mark.parametrize(
    ("operation", "expected"),
    [
        ("create", "docker_create_failed"),
        ("start", "docker_start_failed"),
        ("wait", "docker_wait_failed"),
        ("stop", "docker_stop_failed"),
        ("remove", "docker_destroy_failed"),
        ("list", "docker_inventory_failed"),
    ],
)
async def test_engine_failures_are_reduced_to_safe_codes(
    operation: str,
    expected: str,
) -> None:
    engine = MemoryDockerEngine()
    engine.failure[operation] = RuntimeError("socket path and private engine detail")
    runtime = DockerWorkerRuntime(engine, policy(), clock=lambda: NOW)

    with pytest.raises(DockerRuntimeError, match=expected) as captured:
        await _invoke_operation(runtime, operation)
    assert "socket" not in str(captured.value)


async def test_inventory_rejects_missing_or_foreign_ownership_labels() -> None:
    engine = MemoryDockerEngine()
    runtime = DockerWorkerRuntime(engine, policy(), clock=lambda: NOW)
    await runtime.create(request(), worker_id=WORKER_ID)
    assert engine.spec is not None
    labels = dict(engine.spec.labels)
    labels.pop("io.vuln-proof-claw.request-id")
    engine.containers = (
        OwnedContainer(reference=REFERENCE, labels=tuple(labels.items())),
    )
    with pytest.raises(DockerRuntimeError, match="docker_inventory_failed"):
        await runtime.list_resources()

    labels["io.vuln-proof-claw.request-id"] = request().request_id
    labels["io.vuln-proof-claw.runtime-identity"] = "foreign-runtime"
    engine.containers = (
        OwnedContainer(reference=REFERENCE, labels=tuple(labels.items())),
    )
    with pytest.raises(DockerRuntimeError, match="docker_inventory_failed"):
        await runtime.list_resources()


def test_privileged_container_metadata_never_appears_in_representations() -> None:
    result = ContainerWaitResult(exit_code=1, output=b"secret worker output")
    container = OwnedContainer(reference=REFERENCE, labels=())

    assert "secret worker output" not in repr(result)
    assert REFERENCE not in repr(container)


def test_container_spec_has_no_escape_hatch_fields() -> None:
    names = {value.name for value in fields(RestrictedContainerSpec)}

    assert names.isdisjoint(
        {
            "command",
            "devices",
            "entrypoint",
            "environment",
            "host_network",
            "mounts",
            "privileged",
            "volumes",
        }
    )


async def _invoke_operation(runtime: DockerWorkerRuntime, operation: str) -> None:
    if operation == "create":
        await runtime.create(request(), worker_id=WORKER_ID)
    elif operation == "start":
        await runtime.start(REFERENCE)
    elif operation == "wait":
        await runtime.wait(REFERENCE)
    elif operation == "stop":
        await runtime.cancel(REFERENCE)
    elif operation == "remove":
        await runtime.destroy(REFERENCE)
    else:
        await runtime.list_resources()
