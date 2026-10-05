"""End-to-end proof that every gate on the control-plane walk refuses without side effects.

Each test drives the real API chain and asserts two things at the seam: the refusal fires,
and the consequence the refused step would have had never landed. A refusal that still
queues an action, starts a worker, appends evidence, or writes the audit event for the
step it rejected is the failure mode these tests exist to catch.
"""

from __future__ import annotations

from pathlib import Path

from httpx import AsyncClient

from tests.api.test_approvals import (
    APPROVER_HEADERS,
    OPERATOR_HEADERS,
    authenticated_client,
)
from tests.api.test_assessments import FakeAssessmentTransport, assessment_client
from tests.api.test_workflow import _create_engagement, _create_task
from vuln_proof_claw.config.models import AssessmentConfig

# Every audit event family that only an executed step may write.
_EXECUTION_EVENT_PREFIXES = ("worker.", "assessment.", "evidence.", "approval.")

# The exact request the assessment service builds for a target, expressed as the
# workflow API expresses it. Proposing an action with these protected fields lets the
# assessment endpoint adopt it by idempotency key, which is the only way to drive the
# pre-execution authorization gate through the public API.
# The user agent is read from the configured default rather than restated: the
# adoption path compares the proposal against the request the endpoint builds,
# so a literal copy here goes red on every version bump for no real reason.
_ASSESSMENT_HEADERS = {
    "Accept": "text/html,application/xhtml+xml,application/json",
    "User-Agent": AssessmentConfig().user_agent,
}


async def _destructive_engagement(
    client: AsyncClient,
    *,
    destructive_actions_enabled: bool,
) -> str:
    """Create an L4-ceiling engagement so only the destructive switch can refuse."""
    project = await client.post("/api/v1/projects", json={"name": "Destructive gate"})
    assert project.status_code == 201
    engagement = await client.post(
        f"/api/v1/projects/{project.json()['id']}/engagements",
        json={
            "name": "Destructive gate engagement",
            "starts_at": "2026-08-01T00:00:00Z",
            "ends_at": "2027-08-02T00:00:00Z",
            "maximum_risk": "L4",
            "destructive_actions_enabled": destructive_actions_enabled,
            "scope": {
                "allowed_hostnames": ["api.example.test"],
                "allowed_ports": [443],
                "allowed_schemes": ["https"],
                "allowed_paths": ["/v1"],
            },
        },
    )
    assert engagement.status_code == 201
    return str(engagement.json()["id"])


async def _audit_event_types(client: AsyncClient, engagement_id: str) -> list[str]:
    response = await client.get(f"/api/v1/engagements/{engagement_id}/audit-events")
    assert response.status_code == 200
    return [str(item["event_type"]) for item in response.json()["items"]]


async def _assert_nothing_executed(client: AsyncClient, engagement_id: str) -> None:
    """Assert the refused step left no evidence, no finding, and no execution audit."""
    report = await client.get(f"/api/v1/engagements/{engagement_id}/report")
    assert report.status_code == 200
    assert report.json()["counts"]["evidence"] == 0
    assert report.json()["counts"]["findings"] == 0
    events = await _audit_event_types(client, engagement_id)
    assert [item for item in events if item.startswith(_EXECUTION_EVENT_PREFIXES)] == []


async def _propose(
    client: AsyncClient,
    task_id: str,
    body: dict[str, object],
) -> dict[str, object]:
    """Propose one HTTP action and return the gate's verdict on it."""
    response = await client.post(f"/api/v1/tasks/{task_id}/http-actions", json=body)
    assert response.status_code == 201
    return dict(response.json())


async def test_out_of_scope_target_is_refused_by_scope_and_by_the_action_gate(
    tmp_path: Path,
) -> None:
    """Case 1: scope refuses the target, and the action gate refuses it the same way."""
    async with authenticated_client(tmp_path / "scope-gate.db") as client:
        client.headers.update(OPERATOR_HEADERS)
        engagement_id = await _create_engagement(client)
        _, task_id = await _create_task(client, engagement_id)
        evaluated = await client.post(
            f"/api/v1/engagements/{engagement_id}/scope/evaluate",
            json={"target": "https://other.example.test/v1"},
        )
        action = await _propose(
            client,
            task_id,
            {
                "action_type": "public_page_read",
                "target": "https://other.example.test/v1",
                "idempotency_key": "out-of-scope",
            },
        )
        fetched = await client.get(f"/api/v1/actions/{action['id']}")
        approval = await client.get(f"/api/v1/actions/{action['id']}/approval")
        events = await _audit_event_types(client, engagement_id)
        await _assert_nothing_executed(client, engagement_id)

    # The scope itself rejects the target, and the action gate quotes the same reason.
    assert evaluated.status_code == 200
    assert evaluated.json()["allowed"] is False
    assert evaluated.json()["reason"] == "host_not_allowed"
    assert action["state"] == "denied"
    assert action["policy_reason"] == "host_not_allowed"
    # Nothing downstream: the action never reached queued, and no approval exists.
    assert fetched.json()["state"] == "denied"
    assert fetched.json()["approval_id"] is None
    assert approval.status_code == 404
    assert approval.json()["detail"] == "approval_not_found"
    # The refusal itself is recorded; nothing beyond it is.
    assert events.count("policy.decision") == 1
    assert events.count("action.proposed") == 1


async def test_action_above_the_engagement_ceiling_is_denied_and_cannot_be_approved(
    tmp_path: Path,
) -> None:
    """Case 2: the risk ceiling denies outright; the denial cannot be laundered."""
    async with authenticated_client(tmp_path / "risk-ceiling.db") as client:
        client.headers.update(OPERATOR_HEADERS)
        engagement_id = await _create_engagement(client, maximum_risk="L1")
        _, task_id = await _create_task(client, engagement_id)
        action = await _propose(
            client,
            task_id,
            {
                "action_type": "exploit_attempt",
                "target": "https://api.example.test/v1/users",
                "idempotency_key": "over-ceiling",
            },
        )
        approve = await client.post(
            f"/api/v1/actions/{action['id']}/approval-decision",
            json={"decision": "approve", "reason": "try to lift the ceiling"},
            headers=APPROVER_HEADERS,
        )
        fetched = await client.get(f"/api/v1/actions/{action['id']}")
        await _assert_nothing_executed(client, engagement_id)

    # A ceiling breach is a hard deny, not an approval request.
    assert action["risk_level"] == "L2"
    assert action["state"] == "denied"
    assert action["policy_reason"] == "risk_exceeds_engagement_maximum"
    # Nothing downstream: the approver cannot turn the denial into authority.
    assert approve.status_code == 409
    assert approve.json()["detail"] == "action_not_pending_approval"
    assert fetched.json()["state"] == "denied"
    assert fetched.json()["approval_id"] is None


async def test_destructive_action_is_refused_only_while_destructive_mode_is_off(
    tmp_path: Path,
) -> None:
    """Case 3: the destructive switch is what refuses, proven by flipping only it."""
    async with authenticated_client(tmp_path / "destructive.db") as client:
        client.headers.update(OPERATOR_HEADERS)
        disabled_id = await _destructive_engagement(client, destructive_actions_enabled=False)
        _, disabled_task = await _create_task(client, disabled_id)
        refused = await _propose(
            client,
            disabled_task,
            {
                "action_type": "data_deletion",
                "target": "https://api.example.test/v1/records",
                "idempotency_key": "destructive-off",
            },
        )
        refused_approval = await client.post(
            f"/api/v1/actions/{refused['id']}/approval-decision",
            json={"decision": "approve"},
            headers=APPROVER_HEADERS,
        )
        await _assert_nothing_executed(client, disabled_id)

        enabled_id = await _destructive_engagement(client, destructive_actions_enabled=True)
        _, enabled_task = await _create_task(client, enabled_id)
        permitted = await _propose(
            client,
            enabled_task,
            {
                "action_type": "data_deletion",
                "target": "https://api.example.test/v1/records",
                "idempotency_key": "destructive-on",
            },
        )

    # Same risk level, same target, same ceiling: only the switch differs.
    assert refused["risk_level"] == permitted["risk_level"] == "L4"
    assert refused["state"] == "denied"
    assert refused["policy_reason"] == "destructive_actions_disabled"
    # Nothing downstream: no approval path opens for a destructive-mode denial.
    assert refused_approval.status_code == 409
    assert refused_approval.json()["detail"] == "action_not_pending_approval"
    # With the switch on the same proposal reaches the approval gate instead.
    assert permitted["state"] == "pending_approval"
    assert permitted["policy_reason"] == "explicit_approval_required"


async def test_l2_action_is_refused_without_an_approval_and_permitted_with_one(
    tmp_path: Path,
) -> None:
    """Case 4: the approval, and only the approval, changes the outcome."""
    async with authenticated_client(tmp_path / "approval-pair.db") as client:
        client.headers.update(OPERATOR_HEADERS)
        engagement_id = await _create_engagement(client, maximum_risk="L2")
        _, task_id = await _create_task(client, engagement_id)
        action = await _propose(
            client,
            task_id,
            {
                "action_type": "exploit_attempt",
                "target": "https://api.example.test/v1/users",
                "idempotency_key": "needs-approval",
            },
        )
        # Refused half: the same action, before any approval exists.
        unapproved = await client.get(f"/api/v1/actions/{action['id']}")
        missing_approval = await client.get(f"/api/v1/actions/{action['id']}/approval")
        events_before = await _audit_event_types(client, engagement_id)
        await _assert_nothing_executed(client, engagement_id)

        # Permitted half: nothing changes but the approver's decision.
        granted = await client.post(
            f"/api/v1/actions/{action['id']}/approval-decision",
            json={"decision": "approve", "reason": "Authorized validation"},
            headers=APPROVER_HEADERS,
        )
        approved = await client.get(f"/api/v1/actions/{action['id']}")
        approval = await client.get(
            f"/api/v1/actions/{action['id']}/approval",
            headers=APPROVER_HEADERS,
        )
        events_after = await _audit_event_types(client, engagement_id)

    assert action["state"] == "pending_approval"
    assert action["policy_reason"] == "explicit_approval_required"
    assert unapproved.json()["state"] == "pending_approval"
    assert unapproved.json()["approval_id"] is None
    assert missing_approval.status_code == 404
    assert "approval.granted" not in events_before

    assert granted.status_code == 200
    assert granted.json()["state"] == "queued"
    assert approved.json()["state"] == "queued"
    # The approval is bound to this exact action, single use, unconsumed.
    assert approved.json()["approval_id"] == granted.json()["approval"]["id"]
    assert approval.status_code == 200
    assert approval.json()["permitted_executions"] == 1
    assert approval.json()["consumed_executions"] == 0
    assert events_after.count("approval.granted") == 1
    assert [item for item in events_after if item.startswith("worker.")] == []


async def test_replayed_single_use_approval_is_refused_without_minting_new_authority(
    tmp_path: Path,
) -> None:
    """Case 5: replaying the grant is refused and never advances the consumed count."""
    async with authenticated_client(tmp_path / "approval-replay.db") as client:
        client.headers.update(OPERATOR_HEADERS)
        engagement_id = await _create_engagement(client, maximum_risk="L2")
        _, task_id = await _create_task(client, engagement_id)
        action = await _propose(
            client,
            task_id,
            {
                "action_type": "exploit_attempt",
                "target": "https://api.example.test/v1/users",
                "idempotency_key": "single-use",
            },
        )
        granted = await client.post(
            f"/api/v1/actions/{action['id']}/approval-decision",
            json={"decision": "approve"},
            headers=APPROVER_HEADERS,
        )
        preset = await client.post(
            f"/api/v1/engagements/{engagement_id}/approval-presets",
            json={
                "name": "Reviewed exploit validation",
                "action_types": ["exploit_attempt"],
                "target_prefixes": ["https://api.example.test/v1/"],
                "maximum_risk": "L2",
            },
            headers=APPROVER_HEADERS,
        )
        replayed_decision = await client.post(
            f"/api/v1/actions/{action['id']}/approval-decision",
            json={"decision": "approve"},
            headers=APPROVER_HEADERS,
        )
        replayed_preset = await client.post(
            f"/api/v1/actions/{action['id']}/apply-approval-preset",
            json={"preset_id": preset.json()["id"]},
        )
        approval = await client.get(
            f"/api/v1/actions/{action['id']}/approval",
            headers=APPROVER_HEADERS,
        )
        fetched = await client.get(f"/api/v1/actions/{action['id']}")
        events = await _audit_event_types(client, engagement_id)

    assert granted.status_code == 200
    assert preset.status_code == 201
    # Both replay routes to a second grant are refused.
    assert replayed_decision.status_code == 409
    assert replayed_decision.json()["detail"] == "action_not_pending_approval"
    assert replayed_preset.status_code == 409
    assert replayed_preset.json()["detail"] == "action_not_pending_approval"
    # Nothing downstream: one approval, still bound, still unconsumed.
    assert approval.json()["id"] == granted.json()["approval"]["id"]
    assert approval.json()["consumed_executions"] == 0
    assert approval.json()["consumed_executions"] <= approval.json()["permitted_executions"]
    assert fetched.json()["approval_id"] == granted.json()["approval"]["id"]
    assert events.count("approval.granted") == 1
    assert [item for item in events if item.startswith("worker.")] == []


async def test_assessment_lookup_refuses_an_action_bound_to_another_engagement(
    tmp_path: Path,
) -> None:
    """Case 6: the engagement/action binding is checked, not assumed."""
    transport = FakeAssessmentTransport()
    async with assessment_client(tmp_path / "cross-engagement.db", transport) as client:
        client.headers.update(OPERATOR_HEADERS)
        owner_id = await _create_engagement(client)
        executed = await client.post(
            f"/api/v1/engagements/{owner_id}/assessments",
            json={"target": "https://api.example.test/v1"},
            headers={"Idempotency-Key": "owner-baseline"},
        )
        action_id = executed.json()["action_id"]

        other_id = await _create_engagement(client)
        _, other_task = await _create_task(client, other_id)
        proposed = await _propose(
            client,
            other_task,
            {
                "action_type": "public_page_read",
                "target": "https://api.example.test/v1",
                "idempotency_key": "not-an-assessment",
            },
        )
        cross_engagement = await client.get(
            f"/api/v1/engagements/{other_id}/assessments/{action_id}"
        )
        wrong_action_type = await client.get(
            f"/api/v1/engagements/{other_id}/assessments/{proposed['id']}"
        )
        owner_view = await client.get(
            f"/api/v1/engagements/{owner_id}/assessments/{action_id}"
        )
        other_report = await client.get(f"/api/v1/engagements/{other_id}/report")
        other_events = await _audit_event_types(client, other_id)

    assert executed.status_code == 201
    assert executed.json()["state"] == "succeeded"
    # The mismatch is refused rather than resolving to the other engagement's action.
    assert cross_engagement.status_code == 404
    assert cross_engagement.json()["detail"] == "assessment_not_found"
    # The same guard rejects an action of the wrong type inside its own engagement.
    assert wrong_action_type.status_code == 404
    # Nothing downstream: the borrowing engagement gained no evidence, findings, or audit.
    assert other_report.json()["counts"] == {"actions": 1, "evidence": 0, "findings": 0}
    assert [item for item in other_events if item.startswith(_EXECUTION_EVENT_PREFIXES)] == []
    # And the owning engagement's action was neither re-run nor re-closed.
    assert owner_view.status_code == 200
    assert owner_view.json()["state"] == "succeeded"
    assert owner_view.json()["evidence_ids"] == executed.json()["evidence_ids"]
    assert len(transport.calls) == 1


async def test_cancelled_action_cannot_be_reopened_by_the_execution_path(
    tmp_path: Path,
) -> None:
    """Case 7: cancel closes the gate the executing endpoint would otherwise walk through."""
    transport = FakeAssessmentTransport()
    async with assessment_client(tmp_path / "cancel-then-run.db", transport) as client:
        client.headers.update(OPERATOR_HEADERS)
        engagement_id = await _create_engagement(client)
        _, task_id = await _create_task(client, engagement_id)
        # Propose the exact protected request the assessment endpoint would build, so the
        # endpoint adopts this action instead of creating a fresh one.
        action = await _propose(
            client,
            task_id,
            {
                "action_type": "passive_fingerprint",
                "headers": _ASSESSMENT_HEADERS,
                "target": "https://api.example.test/v1",
                "idempotency_key": "assessment:cancel-then-run",
            },
        )
        cancelled = await client.post(
            f"/api/v1/actions/{action['id']}/cancel",
            json={"reason": "Objective changed"},
        )
        run_after_cancel = await client.post(
            f"/api/v1/engagements/{engagement_id}/assessments",
            json={"target": "https://api.example.test/v1"},
            headers={"Idempotency-Key": "cancel-then-run"},
        )
        cancel_replay = await client.post(
            f"/api/v1/actions/{action['id']}/cancel",
            json={},
        )
        fetched = await client.get(f"/api/v1/actions/{action['id']}")
        history = await client.get("/api/v1/assessments")
        events = await _audit_event_types(client, engagement_id)
        await _assert_nothing_executed(client, engagement_id)

    assert action["state"] == "queued"
    assert cancelled.status_code == 200
    assert cancelled.json()["state"] == "cancelled"
    # The executing endpoint adopts the cancelled action and refuses to run it.
    assert run_after_cancel.status_code == 200
    assert run_after_cancel.json()["action_id"] == action["id"]
    assert run_after_cancel.json()["state"] == "cancelled"
    assert run_after_cancel.json()["replayed"] is True
    assert run_after_cancel.json()["evidence_ids"] == []
    assert run_after_cancel.json()["findings_count"] == 0
    # Nothing downstream: no request left the control plane and the action stays terminal.
    assert len(transport.calls) == 0
    assert cancel_replay.status_code == 409
    assert cancel_replay.json()["detail"] == "action_already_terminal"
    assert fetched.json()["state"] == "cancelled"
    assert history.json()["items"][0]["action_id"] == action["id"]
    assert history.json()["items"][0]["state"] == "cancelled"
    assert history.json()["items"][0]["evidence_count"] == 0
    assert events.count("action.cancelled") == 1
