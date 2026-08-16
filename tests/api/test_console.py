"""Tests for the first Web console API surface."""

from __future__ import annotations

from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from datetime import UTC, datetime, timedelta
from pathlib import Path

from fastapi import FastAPI
from httpx import ASGITransport, AsyncClient
from pydantic import SecretStr

from vuln_proof_claw.api.app import create_app
from vuln_proof_claw.config.models import DatabaseConfig, WebConfig
from vuln_proof_claw.config.settings import Settings
from vuln_proof_claw.persistence.base import Base
from vuln_proof_claw.persistence.session import create_engine


@asynccontextmanager
async def console_client(database_path: Path) -> AsyncIterator[AsyncClient]:
    database_url = f"sqlite:///{database_path}"
    engine = create_engine(database_url)
    Base.metadata.create_all(engine)
    engine.dispose()
    app = create_app(
        Settings(
            database=DatabaseConfig(url=SecretStr(database_url)),
            web=WebConfig(enabled=False),
        )
    )
    async with app.router.lifespan_context(app), AsyncClient(
        transport=ASGITransport(app=app),
        base_url="http://testserver",
    ) as client:
        yield client


async def test_dashboard_starts_with_truthful_empty_state(tmp_path: Path) -> None:
    async with console_client(tmp_path / "console.db") as client:
        response = await client.get("/api/v1/dashboard/summary")

    assert response.status_code == 200
    assert response.json() == {
        "schema_version": "v1",
        "counts": {
            "projects": 0,
            "engagements": 0,
            "active_actions": 0,
            "pending_approvals": 0,
            "evidence": 0,
            "findings": 0,
        },
        "recent_projects": [],
        "execution_available": False,
        "phase": "web-foundation",
    }


async def test_project_can_be_created_and_listed(tmp_path: Path) -> None:
    async with console_client(tmp_path / "projects.db") as client:
        created = await client.post("/api/v1/projects", json={"name": "  Acme API  "})
        listed = await client.get("/api/v1/projects")
        dashboard = await client.get("/api/v1/dashboard/summary")

    assert created.status_code == 201
    assert created.json()["name"] == "Acme API"
    assert listed.status_code == 200
    assert listed.json()["total"] == 1
    assert listed.json()["items"][0] == created.json()
    assert dashboard.json()["counts"]["projects"] == 1
    assert dashboard.json()["recent_projects"][0] == created.json()


async def test_project_name_rejects_whitespace_only_value(tmp_path: Path) -> None:
    async with console_client(tmp_path / "validation.db") as client:
        response = await client.post("/api/v1/projects", json={"name": "   "})

    assert response.status_code == 422


async def test_scoped_engagement_can_be_created_listed_and_reported(tmp_path: Path) -> None:
    # Use a window around the current instant so scope evaluation stays valid
    # regardless of the calendar date the suite runs on.
    now = datetime.now(UTC).replace(microsecond=0)
    starts_at = (now - timedelta(days=1)).strftime("%Y-%m-%dT%H:%M:%SZ")
    ends_at = (now + timedelta(days=1)).strftime("%Y-%m-%dT%H:%M:%SZ")
    payload = {
        "name": "Production API assessment",
        "starts_at": starts_at,
        "ends_at": ends_at,
        "maximum_risk": "L2",
        "scope": {
            "allowed_hostnames": ["API.Example.TEST."],
            "allowed_ports": [443],
            "allowed_schemes": ["HTTPS"],
            "allowed_paths": ["/v1/../v1"],
            "denied_paths": ["/v1/admin"],
        },
    }
    async with console_client(tmp_path / "engagement.db") as client:
        project = await client.post("/api/v1/projects", json={"name": "Acme"})
        project_id = project.json()["id"]
        created = await client.post(
            f"/api/v1/projects/{project_id}/engagements",
            json=payload,
        )
        listed = await client.get(f"/api/v1/projects/{project_id}/engagements")
        fetched = await client.get(f"/api/v1/engagements/{created.json()['id']}")
        allowed = await client.post(
            f"/api/v1/engagements/{created.json()['id']}/scope/evaluate",
            json={"target": "HTTPS://API.EXAMPLE.TEST:443/v1/users"},
        )
        denied = await client.post(
            f"/api/v1/engagements/{created.json()['id']}/scope/evaluate",
            json={"target": "https://api.example.test/v1/admin"},
        )
        report = await client.get(f"/api/v1/engagements/{created.json()['id']}/report")
        markdown = await client.get(f"/api/v1/engagements/{created.json()['id']}/report.md")

    assert created.status_code == 201
    assert created.json()["scope"]["allowed_hostnames"] == ["api.example.test"]
    assert created.json()["scope"]["allowed_schemes"] == ["https"]
    assert created.json()["scope"]["allowed_paths"] == ["/v1"]
    assert created.json()["scope"]["valid_from"] == starts_at
    assert created.json()["scope"]["valid_until"] == ends_at
    assert listed.json()["items"] == [created.json()]
    assert fetched.json() == created.json()
    assert allowed.json() == {
        "schema_version": "v1",
        "allowed": True,
        "reason": "scope_allowed",
        "normalized_target": "https://api.example.test:443/v1/users",
        "requires_dns_recheck": True,
    }
    assert denied.json()["allowed"] is False
    assert denied.json()["reason"] == "path_denied"
    assert report.status_code == 200
    assert report.json()["counts"] == {"actions": 0, "evidence": 0, "findings": 0}
    assert report.json()["evidence_integrity"] == {
        "status": "valid",
        "checked_records": 0,
        "reason": None,
    }
    assert report.json()["raw_evidence_included"] is False
    assert markdown.status_code == 200
    assert "# Engagement report: Production API assessment" in markdown.text
    assert "No findings have been recorded." in markdown.text


async def test_engagement_requires_existing_project_and_explicit_allow_scope(
    tmp_path: Path,
) -> None:
    payload = {
        "name": "Invalid",
        "starts_at": "2026-08-01T00:00:00Z",
        "ends_at": "2026-08-02T00:00:00Z",
        "scope": {"allowed_hostnames": ["example.test"]},
    }
    async with console_client(tmp_path / "engagement-validation.db") as client:
        missing = await client.post(
            "/api/v1/projects/01999999-9999-7999-8999-999999999999/engagements",
            json=payload,
        )
        project = await client.post("/api/v1/projects", json={"name": "Acme"})
        payload["scope"] = {}
        empty_scope = await client.post(
            f"/api/v1/projects/{project.json()['id']}/engagements",
            json=payload,
        )

    assert missing.status_code == 404
    assert empty_scope.status_code == 422


async def test_scope_window_cannot_exceed_engagement_window(tmp_path: Path) -> None:
    payload = {
        "name": "Overbroad scope",
        "starts_at": "2026-08-01T00:00:00Z",
        "ends_at": "2026-08-02T00:00:00Z",
        "scope": {
            "allowed_hostnames": ["example.test"],
            "valid_from": "2026-07-31T23:59:59Z",
            "valid_until": "2026-08-02T00:00:01Z",
        },
    }
    async with console_client(tmp_path / "scope-window.db") as client:
        project = await client.post("/api/v1/projects", json={"name": "Acme"})
        response = await client.post(
            f"/api/v1/projects/{project.json()['id']}/engagements",
            json=payload,
        )

    assert response.status_code == 422
    assert response.json()["detail"] == "scope must not start before its engagement"


async def test_web_console_serves_configured_static_bundle(tmp_path: Path) -> None:
    web_root = tmp_path / "web"
    assets = web_root / "assets"
    assets.mkdir(parents=True)
    (web_root / "index.html").write_text("<!doctype html><title>ProofClaw</title>")
    (assets / "app.js").write_text("console.log('proofclaw')")
    app: FastAPI = create_app(
        Settings(web=WebConfig(static_directory=web_root)),
    )

    async with AsyncClient(
        transport=ASGITransport(app=app),
        base_url="http://testserver",
    ) as client:
        index = await client.get("/")
        asset = await client.get("/assets/app.js")

    assert index.status_code == 200
    assert "ProofClaw" in index.text
    assert asset.status_code == 200
    assert "proofclaw" in asset.text
