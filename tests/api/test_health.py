"""Tests for versioned liveness, readiness, and OpenAPI contracts."""

from __future__ import annotations

import json
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager

from fastapi import FastAPI
from httpx import ASGITransport, AsyncClient
from pydantic import SecretStr

from vuln_proof_claw import __version__
from vuln_proof_claw.api.app import create_app
from vuln_proof_claw.api.dependencies import ProbeResult
from vuln_proof_claw.config.models import ApiConfig, DatabaseConfig, ProviderConfig
from vuln_proof_claw.config.settings import Settings
from vuln_proof_claw.domain.identifiers import new_identifier


class FakeProbe:
    def __init__(self, result: ProbeResult) -> None:
        self._result = result
        self.calls = 0

    def check(self) -> ProbeResult:
        self.calls += 1
        return self._result


@asynccontextmanager
async def api_client(app: FastAPI) -> AsyncIterator[AsyncClient]:
    async with app.router.lifespan_context(app), AsyncClient(
        transport=ASGITransport(app=app),
        base_url="http://testserver",
    ) as client:
        yield client


async def test_liveness_has_no_dependency_checks() -> None:
    probe = FakeProbe(ProbeResult("database", False, "database_unavailable"))

    async with api_client(create_app(Settings(), database_probe=probe)) as client:
        response = await client.get("/api/v1/health/live")

    assert response.status_code == 200
    assert response.json() == {
        "schema_version": "v1",
        "service": "vuln-proof-claw",
        "status": "ok",
        "version": __version__,
    }
    assert probe.calls == 0


async def test_readiness_returns_versioned_success_contract() -> None:
    probe = FakeProbe(ProbeResult("database", True, "database_ready"))

    async with api_client(create_app(Settings(), database_probe=probe)) as client:
        response = await client.get("/api/v1/health/ready")

    assert response.status_code == 200
    assert response.json() == {
        "schema_version": "v1",
        "service": "vuln-proof-claw",
        "status": "ready",
        "checks": [
            {
                "name": "configuration",
                "status": "ready",
                "code": "configuration_ready_development",
            },
            {
                "name": "database",
                "status": "ready",
                "code": "database_ready",
            },
        ],
    }
    assert probe.calls == 1


async def test_readiness_failure_is_safe_and_does_not_break_liveness() -> None:
    probe = FakeProbe(ProbeResult("database", False, "database_unavailable"))

    async with api_client(create_app(Settings(), database_probe=probe)) as client:
        readiness = await client.get("/api/v1/health/ready")
        liveness = await client.get("/api/v1/health/live")

    assert readiness.status_code == 503
    assert readiness.json()["status"] == "not_ready"
    assert readiness.json()["checks"][1] == {
        "name": "database",
        "status": "not_ready",
        "code": "database_unavailable",
    }
    assert liveness.status_code == 200


async def test_default_database_probe_executes_connectivity_check() -> None:
    settings = Settings(database=DatabaseConfig(url=SecretStr("sqlite+pysqlite:///:memory:")))

    async with api_client(create_app(settings)) as client:
        response = await client.get("/api/v1/health/ready")

    assert response.status_code == 200
    assert response.json()["checks"][1]["code"] == "database_ready"


async def test_invalid_database_configuration_keeps_liveness_available() -> None:
    settings = Settings(database=DatabaseConfig(url=SecretStr("not-a-database-url")))

    async with api_client(create_app(settings)) as client:
        liveness = await client.get("/api/v1/health/live")
        readiness = await client.get("/api/v1/health/ready")

    assert liveness.status_code == 200
    assert readiness.status_code == 503
    assert readiness.json()["checks"][1]["code"] == "database_configuration_invalid"


def test_openapi_is_stable_and_does_not_expose_secrets() -> None:
    database_marker = new_identifier()
    provider_secret = new_identifier()
    operator_secret = new_identifier()
    approver_secret = new_identifier()
    database_secret = f"postgresql+psycopg://private-user:{database_marker}@db/private"
    settings = Settings(
        api=ApiConfig(
            authentication_ready=True,
            operator_token=SecretStr(operator_secret),
            approver_token=SecretStr(approver_secret),
        ),
        database=DatabaseConfig(url=SecretStr(database_secret)),
        provider=ProviderConfig(api_key=SecretStr(provider_secret)),
    )
    app = create_app(
        settings,
        database_probe=FakeProbe(ProbeResult("database", True, "database_ready")),
    )

    document = app.openapi()
    serialized = json.dumps(document)

    assert document["info"]["version"] == __version__
    assert "/api/v1/health/live" in document["paths"]
    assert "/api/v1/health/ready" in document["paths"]
    assert database_secret not in serialized
    assert provider_secret not in serialized
    assert operator_secret not in serialized
    assert approver_secret not in serialized
    assert database_marker not in serialized
    assert document["components"]["securitySchemes"]["HTTPBearer"]["scheme"] == "bearer"
    assert "security" not in document["paths"]["/api/v1/health/live"]["get"]
