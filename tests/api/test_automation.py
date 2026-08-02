from __future__ import annotations

from pathlib import Path

from tests.api.test_console import console_client
from tests.api.test_workflow import _create_engagement


async def test_automation_plan_creates_role_separated_audited_actions(tmp_path: Path) -> None:
    async with console_client(tmp_path / "automation.db") as client:
        engagement_id = await _create_engagement(client)
        created = await client.post(
            f"/api/v1/engagements/{engagement_id}/automation-plans",
            json={
                "target": "https://api.example.test/v1/users/7?limit=10",
                "checks": ["cors", "authentication", "authorization", "input_validation"],
                "mutations": [
                    {"location": "query", "name": "limit", "strategy": "boundary"}
                ],
                "review_reason": "Review documented inputs",
            },
        )
        audit = await client.get(f"/api/v1/engagements/{engagement_id}/audit-events")

    assert created.status_code == 201
    assert created.json()["planner"] == "deterministic-planner-v1"
    assert created.json()["verifier"] == "deterministic-verifier-v1"
    assert len(created.json()["actions"]) == 4
    assert len(created.json()["mutation_plan_digest"]) == 64
    assert audit.json()["items"][0]["event_type"] == "automation.plan_created"


async def test_verifier_flags_cors_and_requires_reviewed_input_mutations(tmp_path: Path) -> None:
    digest = "a" * 64
    async with console_client(tmp_path / "verifier.db") as client:
        engagement_id = await _create_engagement(client)
        rejected = await client.post(
            f"/api/v1/engagements/{engagement_id}/automation-plans",
            json={
                "target": "https://api.example.test/v1",
                "checks": ["input_validation"],
            },
        )
        verified = await client.post(
            "/api/v1/automation/verify",
            json={
                "check": "cors",
                "supplied_origin": "https://origin.example.test",
                "baseline": {
                    "status_code": 200,
                    "headers": {
                        "Access-Control-Allow-Origin": "*",
                        "Access-Control-Allow-Credentials": "true",
                    },
                    "body_digest": digest,
                    "body_size": 12,
                },
            },
        )

    assert rejected.status_code == 422
    assert rejected.json()["detail"] == "input_validation_requires_reviewed_mutations"
    assert verified.json()["outcome"] == "candidate"
    assert verified.json()["verifier"] == "deterministic-verifier-v1"
