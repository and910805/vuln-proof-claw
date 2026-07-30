"""Tests for typed environment-backed settings."""

from __future__ import annotations

import pytest
from pydantic import ValidationError

from vuln_proof_claw.config.models import Environment
from vuln_proof_claw.config.settings import Settings


def test_defaults_are_local_and_non_production() -> None:
    settings = Settings()

    assert settings.app.environment is Environment.DEVELOPMENT
    assert settings.api.host == "127.0.0.1"
    assert settings.api.authentication_ready is False


def test_nested_environment_variables(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("VULN_PROOF_CLAW_API__PORT", "9090")
    monkeypatch.setenv("VULN_PROOF_CLAW_LOGGING__FORMAT", "json")

    settings = Settings()

    assert settings.api.port == 9090
    assert settings.logging.format == "json"


@pytest.mark.parametrize(
    ("name", "value"),
    [
        ("VULN_PROOF_CLAW_APP__DEBUG", "true"),
        ("VULN_PROOF_CLAW_DATABASE__ECHO", "true"),
    ],
)
def test_unsafe_production_modes_are_rejected(
    monkeypatch: pytest.MonkeyPatch,
    name: str,
    value: str,
) -> None:
    monkeypatch.setenv("VULN_PROOF_CLAW_APP__ENVIRONMENT", "production")
    monkeypatch.setenv(name, value)

    with pytest.raises(ValidationError):
        Settings()


def test_wildcard_production_binding_requires_authentication(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("VULN_PROOF_CLAW_APP__ENVIRONMENT", "production")
    monkeypatch.setenv(
        "VULN_PROOF_CLAW_API__HOST",
        "0.0.0.0",  # noqa: S104 - verifies the production guard
    )

    with pytest.raises(ValidationError, match="authentication readiness"):
        Settings()


def test_worker_runtime_has_no_provider_credentials(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("VULN_PROOF_CLAW_PROVIDER__API_KEY", "top-secret")

    worker = Settings().worker_runtime().model_dump()

    assert all("provider" not in key and "key" not in key for key in worker)
    assert "top-secret" not in repr(worker)
