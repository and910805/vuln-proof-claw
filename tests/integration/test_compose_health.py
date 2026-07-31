"""Static Compose security checks and opt-in live health verification."""

from __future__ import annotations

import os
from pathlib import Path
from typing import Any

import httpx
import pytest
import yaml

REPOSITORY_ROOT = Path(__file__).resolve().parents[2]


def load_compose() -> dict[str, Any]:
    content = (REPOSITORY_ROOT / "compose.yaml").read_text(encoding="utf-8")
    loaded = yaml.safe_load(content)
    assert isinstance(loaded, dict)
    return loaded


def test_compose_has_hardened_local_api_and_unpublished_database() -> None:
    compose = load_compose()
    services = compose["services"]
    api = services["api"]
    database = services["database"]

    assert api["ports"] == ["127.0.0.1:8080:8080"]
    assert api["read_only"] is True
    assert api["cap_drop"] == ["ALL"]
    assert api["security_opt"] == ["no-new-privileges:true"]
    assert api["pids_limit"] == 256
    assert "/api/v1/health/ready" in " ".join(api["healthcheck"]["test"])
    assert "ports" not in database
    assert database["security_opt"] == ["no-new-privileges:true"]
    assert compose["networks"]["worker-isolated"]["internal"] is True
    assert compose["networks"]["worker-isolated"]["name"] == "vuln-proof-claw-workers"


def test_compose_and_images_never_mount_sensitive_host_boundaries() -> None:
    compose_text = (REPOSITORY_ROOT / "compose.yaml").read_text(encoding="utf-8").lower()
    api_dockerfile = (REPOSITORY_ROOT / "Dockerfile").read_text(encoding="utf-8")
    worker_dockerfile = (REPOSITORY_ROOT / "docker/worker/Dockerfile").read_text(
        encoding="utf-8"
    )

    assert "docker.sock" not in compose_text
    assert "/home/" not in compose_text
    assert "privileged:" not in compose_text
    assert "USER 10001:10001" in api_dockerfile
    assert "USER 10002:10002" in worker_dockerfile
    assert "vuln_proof_claw.execution.worker" in worker_dockerfile


def test_worker_security_document_has_bilingual_pair() -> None:
    assert (REPOSITORY_ROOT / "docs/WORKER_SECURITY.md").is_file()
    assert (REPOSITORY_ROOT / "docs/WORKER_SECURITY.zh-TW.md").is_file()


def test_live_compose_readiness_when_explicitly_enabled() -> None:
    if os.getenv("VULN_PROOF_CLAW_RUN_COMPOSE_INTEGRATION") != "1":
        pytest.skip("Compose integration is not enabled")

    response = httpx.get(
        "http://127.0.0.1:8080/api/v1/health/ready",
        timeout=5.0,
    )
    assert response.status_code == httpx.codes.OK
    assert response.json()["status"] == "ready"
