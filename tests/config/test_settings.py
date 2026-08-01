"""Tests for typed environment-backed settings."""

from __future__ import annotations

import pytest
from pydantic import SecretStr, ValidationError

from vuln_proof_claw.config.models import (
    ApiConfig,
    AppConfig,
    AssessmentConfig,
    DockerConfig,
    EngineGatewayConfig,
    Environment,
)
from vuln_proof_claw.config.settings import Settings


def test_defaults_are_local_and_non_production() -> None:
    settings = Settings()

    assert settings.app.environment is Environment.DEVELOPMENT
    assert settings.api.host == "127.0.0.1"
    assert settings.api.authentication_ready is False


def test_nested_environment_variables(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("VULN_PROOF_CLAW_API__PORT", "9090")
    monkeypatch.setenv("VULN_PROOF_CLAW_LOGGING__FORMAT", "json")
    monkeypatch.setenv("VULN_PROOF_CLAW_ASSESSMENT__TIMEOUT_SECONDS", "15")

    settings = Settings()

    assert settings.api.port == 9090
    assert settings.logging.format == "json"
    assert settings.assessment.timeout_seconds == 15


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


def test_authentication_readiness_requires_distinct_long_tokens() -> None:
    with pytest.raises(ValidationError, match="requires operator and approver tokens"):
        ApiConfig(authentication_ready=True)

    repeated = SecretStr("x" * 32)
    with pytest.raises(ValidationError, match="must be distinct"):
        ApiConfig(
            authentication_ready=True,
            operator_token=repeated,
            approver_token=repeated,
        )

    configured = ApiConfig(
        authentication_ready=True,
        operator_token=SecretStr("o" * 32),
        approver_token=SecretStr("a" * 32),
    )
    assert configured.authentication_ready
    assert not configured.evidence_access_ready

    with pytest.raises(ValidationError, match="must be distinct"):
        ApiConfig(
            authentication_ready=True,
            operator_token=SecretStr("o" * 32),
            approver_token=SecretStr("a" * 32),
            evidence_reader_token=SecretStr("o" * 32),
        )

    evidence_ready = configured.model_copy(
        update={"evidence_reader_token": SecretStr("e" * 32)}
    )
    assert evidence_ready.evidence_access_ready


def test_production_assessment_requires_authentication() -> None:
    with pytest.raises(ValidationError, match="passive assessment requires authentication"):
        Settings(
            app=AppConfig(environment=Environment.PRODUCTION),
            assessment=AssessmentConfig(enabled=True),
        )


def test_production_worker_runtime_requires_authentication() -> None:
    with pytest.raises(ValidationError, match="worker runtime requires authentication"):
        Settings(
            app=AppConfig(environment=Environment.PRODUCTION),
            docker=DockerConfig(runtime_enabled=True),
            engine_gateway=EngineGatewayConfig(
                url="https://engine.example.test",
                token=SecretStr("g" * 32),
            ),
        )


def test_enabled_worker_runtime_requires_complete_distinct_gateway_credentials() -> None:
    with pytest.raises(ValidationError, match="authenticated Engine gateway"):
        Settings(docker=DockerConfig(runtime_enabled=True))

    shared = SecretStr("s" * 32)
    with pytest.raises(ValidationError, match="distinct from API tokens"):
        Settings(
            docker=DockerConfig(runtime_enabled=True),
            api=ApiConfig(
                authentication_ready=True,
                operator_token=shared,
                approver_token=SecretStr("a" * 32),
            ),
            engine_gateway=EngineGatewayConfig(
                url="https://engine.example.test",
                token=shared,
            ),
        )


def test_engine_gateway_requires_safe_origin_and_long_token() -> None:
    with pytest.raises(ValidationError, match="configured together"):
        EngineGatewayConfig(url="https://engine.example.test")
    with pytest.raises(ValidationError, match="32 to 4096"):
        EngineGatewayConfig(
            url="https://engine.example.test",
            token=SecretStr("short"),
        )
    with pytest.raises(ValidationError, match="visible ASCII"):
        EngineGatewayConfig(
            url="https://engine.example.test",
            token=SecretStr("g" * 32 + "\n"),
        )
    for unsafe_url in (
        "http://engine.example.test",
        "http://localhost:8081",
        "https://user:password@engine.example.test",
        "https://engine.example.test/api",
        "https://engine.example.test?token=secret",
        "https://engine.example.test:invalid",
    ):
        with pytest.raises(ValidationError):
            EngineGatewayConfig(url=unsafe_url, token=SecretStr("g" * 32))

    ipv4 = EngineGatewayConfig(
        url="http://127.0.0.1:8081/",
        token=SecretStr("g" * 32),
    )
    ipv6 = EngineGatewayConfig(
        url="http://[::1]:8081",
        token=SecretStr("g" * 32),
    )
    assert ipv4.url == "http://127.0.0.1:8081"
    assert ipv6.ready
    assert "g" * 32 not in repr(ipv4)


def test_assessment_user_agent_rejects_header_injection() -> None:
    with pytest.raises(ValidationError, match="must not be blank"):
        AssessmentConfig(user_agent="   ")

    with pytest.raises(ValidationError, match="control delimiter"):
        AssessmentConfig(user_agent="scanner\r\nAuthorization: secret")
