"""Tests for the first Web console API surface."""

from __future__ import annotations

from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
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
