"""Orphan-runtime janitor tests using a non-network fake reapable runtime."""

from __future__ import annotations

import json
from collections.abc import Generator
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
from sqlalchemy import Engine, select

from tests.execution.test_manager import FakeRuntime
from tests.execution.test_protocol import request
from vuln_proof_claw.execution.janitor import (
    OrphanJanitorError,
    OrphanRuntimeJanitor,
)
from vuln_proof_claw.execution.manager import LifecycleWorkerManager
from vuln_proof_claw.persistence.base import Base
from vuln_proof_claw.persistence.models import AuditEventRecord
from vuln_proof_claw.persistence.session import create_engine, create_session_factory

NOW = datetime(2026, 8, 1, 12, 0, tzinfo=UTC)


class FakeReapableRuntime:
    identity = "fake-runtime@sha256:janitor"

    def __init__(self, owned: tuple[str, ...]) -> None:
        self._owned = owned
        self.destroyed: list[str] = []
        self.list_error: Exception | None = None
        self.destroy_failures: frozenset[str] = frozenset()

    async def list_owned(self) -> tuple[str, ...]:
        if self.list_error is not None:
            raise self.list_error
        return self._owned

    async def destroy(self, runtime_reference: str) -> None:
        if runtime_reference in self.destroy_failures:
            raise RuntimeError("private runtime teardown detail")
        self.destroyed.append(runtime_reference)


@pytest.fixture
def engine(tmp_path: Path) -> Generator[Engine, None, None]:
    result = create_engine(f"sqlite:///{tmp_path / 'janitor.db'}", pool_pre_ping=False)
    Base.metadata.create_all(result)
    yield result
    result.dispose()


def _sweep_events(engine: Engine) -> list[dict[str, object]]:
    session_factory = create_session_factory(engine)
    with session_factory() as session:
        rows = session.scalars(
            select(AuditEventRecord).where(
                AuditEventRecord.event_type == "worker.orphans_reclaimed"
            )
        ).all()
        return [json.loads(bytes(row.payload)) for row in rows]


async def test_restart_reclaims_every_owned_reference(engine: Engine) -> None:
    runtime = FakeReapableRuntime(("runtime-a", "runtime-b", "runtime-c"))
    session_factory = create_session_factory(engine)
    with session_factory.begin() as session:
        report = await OrphanRuntimeJanitor(session, runtime, clock=lambda: NOW).sweep(at=NOW)

    assert sorted(runtime.destroyed) == ["runtime-a", "runtime-b", "runtime-c"]
    assert report.scanned == 3
    assert report.protected == 0
    assert report.reclaimed == 3
    assert report.failed == 0
    assert report.orphaned == 3
    events = _sweep_events(engine)
    assert events == [
        {
            "runtime_identity": "fake-runtime@sha256:janitor",
            "scanned": 3,
            "protected": 0,
            "reclaimed": 3,
            "failed": 0,
        }
    ]


async def test_protected_references_are_never_destroyed(engine: Engine) -> None:
    runtime = FakeReapableRuntime(("runtime-live", "runtime-orphan"))
    session_factory = create_session_factory(engine)
    with session_factory.begin() as session:
        report = await OrphanRuntimeJanitor(session, runtime, clock=lambda: NOW).sweep(
            protected_references=("runtime-live",),
            at=NOW,
        )

    assert runtime.destroyed == ["runtime-orphan"]
    assert report.scanned == 2
    assert report.protected == 1
    assert report.reclaimed == 1
    assert report.failed == 0


async def test_destroy_failures_are_counted_and_remaining_orphans_attempted(
    engine: Engine,
) -> None:
    runtime = FakeReapableRuntime(("runtime-a", "runtime-bad", "runtime-c"))
    runtime.destroy_failures = frozenset({"runtime-bad"})
    session_factory = create_session_factory(engine)
    with session_factory.begin() as session:
        report = await OrphanRuntimeJanitor(session, runtime, clock=lambda: NOW).sweep(at=NOW)

    assert sorted(runtime.destroyed) == ["runtime-a", "runtime-c"]
    assert report.reclaimed == 2
    assert report.failed == 1
    events = _sweep_events(engine)
    assert events == [
        {
            "runtime_identity": "fake-runtime@sha256:janitor",
            "scanned": 3,
            "protected": 0,
            "reclaimed": 2,
            "failed": 1,
        }
    ]


async def test_duplicate_owned_references_are_reclaimed_once(engine: Engine) -> None:
    runtime = FakeReapableRuntime(("runtime-a", "runtime-a", "runtime-b"))
    session_factory = create_session_factory(engine)
    with session_factory.begin() as session:
        report = await OrphanRuntimeJanitor(session, runtime, clock=lambda: NOW).sweep(at=NOW)

    assert runtime.destroyed == ["runtime-a", "runtime-b"]
    assert report.reclaimed == 2


async def test_empty_sweep_records_no_audit_event(engine: Engine) -> None:
    runtime = FakeReapableRuntime(())
    session_factory = create_session_factory(engine)
    with session_factory.begin() as session:
        report = await OrphanRuntimeJanitor(session, runtime, clock=lambda: NOW).sweep(at=NOW)

    assert report.orphaned == 0
    assert _sweep_events(engine) == []


async def test_fully_protected_sweep_records_no_audit_event(engine: Engine) -> None:
    runtime = FakeReapableRuntime(("runtime-live",))
    session_factory = create_session_factory(engine)
    with session_factory.begin() as session:
        report = await OrphanRuntimeJanitor(session, runtime, clock=lambda: NOW).sweep(
            protected_references=("runtime-live",),
            at=NOW,
        )

    assert report.orphaned == 0
    assert runtime.destroyed == []
    assert _sweep_events(engine) == []


async def test_enumeration_failure_fails_closed_without_audit(engine: Engine) -> None:
    runtime = FakeReapableRuntime(("runtime-a",))
    runtime.list_error = RuntimeError("private enumeration detail")
    session_factory = create_session_factory(engine)
    with session_factory.begin() as session:
        janitor = OrphanRuntimeJanitor(session, runtime, clock=lambda: NOW)
        with pytest.raises(OrphanJanitorError, match="orphan_enumeration_failed") as caught:
            await janitor.sweep(at=NOW)

    assert runtime.destroyed == []
    assert "private enumeration detail" not in str(caught.value)
    assert _sweep_events(engine) == []


async def test_live_manager_references_protect_running_workers(engine: Engine) -> None:
    lifecycle = LifecycleWorkerManager(FakeRuntime(), clock=lambda: NOW)
    handle = await lifecycle.submit(request())
    await lifecycle.start(handle.worker_id)
    protected = lifecycle.live_runtime_references()
    assert protected == frozenset({"runtime-reference-1"})

    runtime = FakeReapableRuntime(("runtime-reference-1", "runtime-orphan"))
    session_factory = create_session_factory(engine)
    with session_factory.begin() as session:
        report = await OrphanRuntimeJanitor(session, runtime, clock=lambda: NOW).sweep(
            protected_references=protected,
            at=NOW + timedelta(minutes=1),
        )

    assert runtime.destroyed == ["runtime-orphan"]
    assert report.protected == 1
    assert report.reclaimed == 1
