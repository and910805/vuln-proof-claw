"""End-to-end proof that the authorised control-plane legs compose across their seams.

Every leg here is already unit-tested in isolation. What this file asserts is only the
hand-offs: the value one leg stores is the value the next leg binds against, and the
report, bundle, and audit trail all describe *this* engagement rather than merely being
non-empty.
"""

from __future__ import annotations

import json
import zipfile
from io import BytesIO
from pathlib import Path

from httpx import AsyncClient

from tests.api.test_approvals import OPERATOR_HEADERS
from tests.api.test_assessments import FakeAssessmentTransport, assessment_client
from vuln_proof_claw.domain.identifiers import ActionId
from vuln_proof_claw.execution.http_capture import HttpCaptureRequest, capture_parameter_digest
from vuln_proof_claw.reporting.bundle import verify_disclosure_bundle

ONLY_TARGET = "https://api.example.test:443/v1"
PROPOSAL_TARGET = "HTTPS://API.EXAMPLE.TEST:443/v1"
PROPOSAL_HEADERS = {"Accept": "application/json"}


async def _authorised_engagement(client: AsyncClient) -> tuple[str, str]:
    """Leg 1: a project, then an engagement whose scope admits exactly one target."""
    project = await client.post("/api/v1/projects", json={"name": "Composition walk"})
    assert project.status_code == 201
    engagement = await client.post(
        f"/api/v1/projects/{project.json()['id']}/engagements",
        json={
            "name": "Authorised composition walk",
            "starts_at": "2026-08-01T00:00:00Z",
            "ends_at": "2027-08-01T00:00:00Z",
            "maximum_risk": "L0",
            "destructive_actions_enabled": False,
            "scope": {
                "allowed_hostnames": ["api.example.test"],
                "allowed_ports": [443],
                "allowed_schemes": ["https"],
                "allowed_paths": ["/v1"],
                "denied_paths": ["/v1/admin"],
            },
        },
    )
    assert engagement.status_code == 201
    assert engagement.json()["maximum_risk"] == "L0"
    assert engagement.json()["destructive_actions_enabled"] is False
    return str(project.json()["id"]), str(engagement.json()["id"])


async def _flow_and_task(client: AsyncClient, engagement_id: str) -> tuple[str, str]:
    """Leg 2: a flow under the engagement, then a task under that flow."""
    flow = await client.post(
        f"/api/v1/engagements/{engagement_id}/flows",
        json={"objective": "Prove the authorised walk composes"},
    )
    assert flow.status_code == 201
    assert flow.json()["engagement_id"] == engagement_id
    task = await client.post(
        f"/api/v1/flows/{flow.json()['id']}/tasks",
        json={"title": "Read the public API root"},
    )
    assert task.status_code == 201
    assert task.json()["flow_id"] == flow.json()["id"]
    return str(flow.json()["id"]), str(task.json()["id"])


async def test_authorised_walk_composes_from_scope_to_bundle_and_audit(  # noqa: PLR0915
    tmp_path: Path,
) -> None:
    """Walk every leg once, in order, asserting what each one hands the next.

    Deliberately one function: splitting it would hide the hand-offs behind fixtures, and a
    failure here is meant to name the seam that broke.
    """
    transport = FakeAssessmentTransport()
    async with assessment_client(tmp_path / "walk.db", transport) as client:
        client.headers.update(OPERATOR_HEADERS)

        # Leg 1: project -> engagement -> immutable scope.
        project_id, engagement_id = await _authorised_engagement(client)
        # The scope the policy leg will bind against admits the one target and nothing beside it.
        admitted = await client.post(
            f"/api/v1/engagements/{engagement_id}/scope/evaluate",
            json={"target": "https://api.example.test/v1"},
        )
        refused_path = await client.post(
            f"/api/v1/engagements/{engagement_id}/scope/evaluate",
            json={"target": "https://api.example.test/v2"},
        )
        refused_host = await client.post(
            f"/api/v1/engagements/{engagement_id}/scope/evaluate",
            json={"target": "https://other.example.test/v1"},
        )
        assert admitted.json()["allowed"] is True
        assert admitted.json()["normalized_target"] == ONLY_TARGET
        assert refused_path.json()["allowed"] is False
        assert refused_host.json()["allowed"] is False

        # Leg 2: engagement -> flow -> task.
        _flow_id, task_id = await _flow_and_task(client, engagement_id)

        # Leg 3: task -> proposed L0 action, evaluated by policy with no approval needed.
        proposed = await client.post(
            f"/api/v1/tasks/{task_id}/http-actions",
            json={
                "action_type": "Public Page Read",
                "method": "GET",
                "target": PROPOSAL_TARGET,
                "headers": PROPOSAL_HEADERS,
                "idempotency_key": "walk-public-page-read",
            },
        )
        assert proposed.status_code == 201
        assert proposed.json()["engagement_id"] == engagement_id
        assert proposed.json()["task_id"] == task_id
        assert proposed.json()["risk_level"] == "L0"
        assert proposed.json()["state"] == "queued"
        assert proposed.json()["policy_reason"] == "automatic_policy_allow"
        assert proposed.json()["approval_id"] is None
        proposal_id = str(proposed.json()["id"])

        # The two values the execution leg binds an Action to are the normalized target and
        # the parameter digest. Recompute both from the request the caller made and require
        # the stored action to agree; a digest computed over anything else would let a
        # differently-parameterised capture satisfy this Action.
        expected_digest = capture_parameter_digest(
            HttpCaptureRequest(
                action_id=ActionId(proposal_id),
                method="GET",
                target=PROPOSAL_TARGET,
                headers=tuple(PROPOSAL_HEADERS.items()),
            )
        )
        assert proposed.json()["normalized_target"] == ONLY_TARGET
        assert proposed.json()["parameter_digest"] == expected_digest
        reloaded = await client.get(f"/api/v1/actions/{proposal_id}")
        assert reloaded.json()["normalized_target"] == ONLY_TARGET
        assert reloaded.json()["parameter_digest"] == expected_digest

        # Leg 4: engagement -> assessment, keyed by Idempotency-Key.
        endpoint = f"/api/v1/engagements/{engagement_id}/assessments"
        key = {"Idempotency-Key": "walk-assessment-v1"}
        assessed = await client.post(
            endpoint,
            json={"target": "https://api.example.test/v1"},
            headers={**OPERATOR_HEADERS, **key},
        )
        replay = await client.post(
            endpoint,
            json={"target": "https://api.example.test/v1"},
            headers={**OPERATOR_HEADERS, **key},
        )
        assert assessed.status_code == 201
        assert assessed.json()["engagement_id"] == engagement_id
        assessment_id = str(assessed.json()["action_id"])
        assert replay.status_code == 200
        assert replay.json()["replayed"] is True
        assert replay.json()["action_id"] == assessment_id
        # The replay must not have reached the target or produced a second action.
        assert len(transport.calls) == 1
        actions = await client.get(f"/api/v1/engagements/{engagement_id}/actions")
        assert actions.json()["total"] == 2
        assert {item["id"] for item in actions.json()["items"]} == {proposal_id, assessment_id}
        # Both legs normalized the one authorised target identically, while the digest still
        # separates the proposal's parameters from the assessment's.
        assessment_action = next(
            item for item in actions.json()["items"] if item["id"] == assessment_id
        )
        assert assessment_action["normalized_target"] == ONLY_TARGET
        assert assessment_action["parameter_digest"] != expected_digest
        assert transport.calls[0][0].target == ONLY_TARGET

        # Leg 5: assessment -> persisted terminal state with evidence and finding ids.
        fetched = await client.get(f"{endpoint}/{assessment_id}")
        assert fetched.status_code == 200
        assert fetched.json()["state"] == "succeeded"
        assert fetched.json()["error_code"] is None
        assert fetched.json()["evidence_ids"] == assessed.json()["evidence_ids"]
        assert fetched.json()["finding_ids"] == assessed.json()["finding_ids"]
        evidence_ids = list(fetched.json()["evidence_ids"])
        finding_ids = list(fetched.json()["finding_ids"])
        assert len(evidence_ids) == 1
        assert finding_ids

        # Leg 6: engagement -> JSON report carrying exactly what the assessment produced.
        report = await client.get(f"/api/v1/engagements/{engagement_id}/report")
        assert report.status_code == 200
        body = report.json()
        assert body["engagement_id"] == engagement_id
        assert body["project_id"] == project_id
        assert body["counts"] == {"actions": 2, "evidence": 1, "findings": len(finding_ids)}
        assert body["action_states"] == {"queued": 1, "succeeded": 1}
        assert body["evidence_integrity"]["status"] == "valid"
        assert body["scope"]["allowed_paths"] == ["/v1"]
        assert [item["id"] for item in body["evidence"]] == evidence_ids
        # The evidence must hang off the action that captured it, not merely exist.
        assert {item["action_id"] for item in body["evidence"]} == {assessment_id}
        assert [item["id"] for item in body["findings"]] == finding_ids
        assert {
            evidence_id
            for item in body["findings"]
            for evidence_id in item["evidence_ids"]
        } == set(evidence_ids)

        # Leg 7: report -> disclosure bundle, verifiable with no access to this process.
        bundle_response = await client.get(
            f"/api/v1/engagements/{engagement_id}/report.bundle.zip"
        )
        assert bundle_response.status_code == 200
        assert bundle_response.headers["content-type"] == "application/zip"

        # Leg 8: engagement -> audit trail.
        audit = await client.get(f"/api/v1/engagements/{engagement_id}/audit-events")

    bundle_path = tmp_path / "walk-disclosure.zip"
    bundle_path.write_bytes(bundle_response.content)
    verification = verify_disclosure_bundle(bundle_path)
    with zipfile.ZipFile(BytesIO(bundle_response.content)) as archive:
        manifest = json.loads(archive.read("manifest.json"))
        bundled_report = json.loads(archive.read("report.json"))

    assert verification.valid is True
    assert verification.errors == ()
    assert verification.engagement_id == engagement_id
    assert verification.files_checked == len(manifest["files"])
    assert verification.archive_sha256 == bundle_response.headers["x-content-sha256"]
    # The bundle must summarise the report it was built from, not a freshly guessed one.
    assert manifest["workflow_summary"] == {
        "actions": 2,
        "action_states": {"queued": 1, "succeeded": 1},
        "evidence_records": 1,
        "findings": len(finding_ids),
    }
    assert [item["id"] for item in manifest["evidence_chain"]] == evidence_ids
    assert manifest["evidence_chain"][0]["previous_digest"] is None
    assert bundled_report["engagement_id"] == engagement_id
    assert [item["id"] for item in bundled_report["findings"]] == finding_ids

    assert audit.status_code == 200
    # Every recorded step belongs to this engagement, in the order the walk performed them.
    assert {item["engagement_id"] for item in audit.json()["items"]} == {engagement_id}
    chronological = list(reversed(audit.json()["items"]))
    assert [item["event_type"] for item in chronological] == [
        "flow.created",
        "task.created",
        "action.proposed",
        "policy.decision",
        "assessment.created",
        "assessment.completed",
        "assessment.discovery_completed",
    ]
    events = {item["event_type"]: item["payload"] for item in chronological}
    assert events["action.proposed"]["action_id"] == proposal_id
    assert events["action.proposed"]["parameter_digest"] == expected_digest
    assert events["action.proposed"]["target"] == ONLY_TARGET
    assert events["policy.decision"]["action_id"] == proposal_id
    assert events["policy.decision"]["decision"] == "allow"
    assert events["policy.decision"]["reason"] == "automatic_policy_allow"
    assert events["assessment.created"]["action_id"] == assessment_id
    assert events["assessment.created"]["target"] == ONLY_TARGET
    # The completion event names the evidence the report and bundle carry, so a capture
    # that landed under some other action could not close this one silently.
    assert events["assessment.completed"]["action_id"] == assessment_id
    assert events["assessment.completed"]["evidence_id"] == evidence_ids[0]
    assert events["assessment.completed"]["finding_count"] == len(finding_ids)
    assert {item["actor"] for item in chronological} == {"operator@example.test"}


async def test_replay_under_a_different_idempotency_key_is_a_second_walk(
    tmp_path: Path,
) -> None:
    """The Idempotency-Key, not the target, is what makes a replay a replay.

    Leg 4 hands the assessment's identity to legs 5 through 8. Change only that key and the
    same target becomes a second action with its own evidence, and every downstream leg
    counts it.
    """
    transport = FakeAssessmentTransport()
    async with assessment_client(tmp_path / "mutated-key.db", transport) as client:
        client.headers.update(OPERATOR_HEADERS)
        _project_id, engagement_id = await _authorised_engagement(client)
        endpoint = f"/api/v1/engagements/{engagement_id}/assessments"
        payload = {"target": "https://api.example.test/v1"}
        first = await client.post(
            endpoint,
            json=payload,
            headers={**OPERATOR_HEADERS, "Idempotency-Key": "walk-assessment-v1"},
        )
        second = await client.post(
            endpoint,
            json=payload,
            headers={**OPERATOR_HEADERS, "Idempotency-Key": "walk-assessment-v2"},
        )
        report = await client.get(f"/api/v1/engagements/{engagement_id}/report")
        audit = await client.get(f"/api/v1/engagements/{engagement_id}/audit-events")

    assert first.status_code == 201
    assert second.status_code == 201
    assert second.json()["replayed"] is False
    assert second.json()["action_id"] != first.json()["action_id"]
    # A summary rolls evidence up per engagement, so the second run reports its own capture
    # plus the first one's -- the point here is that a second capture happened at all.
    assert len(second.json()["evidence_ids"]) == 2
    assert set(first.json()["evidence_ids"]) < set(second.json()["evidence_ids"])
    assert len(transport.calls) == 2
    assert report.json()["counts"]["actions"] == 2
    assert report.json()["counts"]["evidence"] == 2
    assert report.json()["action_states"] == {"succeeded": 2}
    assert {item["action_id"] for item in report.json()["evidence"]} == {
        str(first.json()["action_id"]),
        str(second.json()["action_id"]),
    }
    created = [
        item["payload"]["action_id"]
        for item in audit.json()["items"]
        if item["event_type"] == "assessment.created"
    ]
    assert sorted(created) == sorted(
        [str(first.json()["action_id"]), str(second.json()["action_id"])]
    )
