"""Worker executor through lifecycle and transactional Evidence integration."""

from __future__ import annotations

import json
from pathlib import Path

from tests.execution.test_lifecycle import NOW, FakeRuntime, seed_action
from tests.execution.test_worker import FakeTransport
from vuln_proof_claw.domain.enums import ActionState, WorkerState
from vuln_proof_claw.evidence.persistence import PersistentEvidenceStore
from vuln_proof_claw.execution.lifecycle import ActionWorkerCoordinator
from vuln_proof_claw.execution.manager import LifecycleWorkerManager
from vuln_proof_claw.execution.worker import evaluate_request
from vuln_proof_claw.persistence.base import Base
from vuln_proof_claw.persistence.repositories import ActionRepository, WorkerExecutionRepository
from vuln_proof_claw.persistence.session import create_engine, create_session_factory


async def test_worker_capture_reaches_evidence_chain_only_through_control_plane(
    tmp_path: Path,
) -> None:
    engine = create_engine(f"sqlite:///{tmp_path / 'worker-pipeline.db'}", pool_pre_ping=False)
    Base.metadata.create_all(engine)
    try:
        engagement, action, worker_request = seed_action(engine)
        worker_response = evaluate_request(
            worker_request.model_dump_json().encode(),
            clock=lambda: NOW,
            transport_factory=lambda _scope: FakeTransport(),
        )
        assert worker_response.evidence_ids == ()
        assert len(worker_response.http_captures) == 1

        runtime = FakeRuntime()
        runtime.response = worker_response
        session_factory = create_session_factory(engine)
        with session_factory.begin() as session:
            coordinator = ActionWorkerCoordinator(session, LifecycleWorkerManager(runtime))
            handle = await coordinator.start(worker_request, actor="operator:integration", at=NOW)
            accepted = await coordinator.collect(handle.worker_id, at=NOW)
            assert len(accepted.evidence_ids) == 1
            assert accepted.http_captures == ()
            raw = PersistentEvidenceStore(session).read_raw(accepted.evidence_ids[0])

        assert raw is not None
        payload = json.loads(raw)
        assert payload["capture_schema"] == "http-v1"
        assert payload["response"]["body_base64"] == "aGVsbG8="
        with session_factory() as session:
            stored_action = ActionRepository(session).get(action.id)
            stored_worker = WorkerExecutionRepository(session).get(handle.worker_id)
            verification = PersistentEvidenceStore(session).verify_engagement(engagement.id)
        assert stored_action is not None
        assert stored_action.entity.state is ActionState.SUCCEEDED
        assert stored_worker is not None
        assert stored_worker.entity.state is WorkerState.COMPLETED
        assert verification.valid
        assert verification.checked_records == 1
    finally:
        engine.dispose()
