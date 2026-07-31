"""Tests for credential-safe doctor diagnostics."""

from __future__ import annotations

import importlib

import httpx
import pytest
from pydantic import SecretStr

from vuln_proof_claw.cli.doctor import (
    DoctorCheck,
    check_api,
    check_database,
    check_docker,
    diagnose,
)
from vuln_proof_claw.config.models import ApiConfig, DatabaseConfig
from vuln_proof_claw.config.settings import WILDCARD_IPV4, Settings, load_settings


def test_api_check_validates_v1_liveness(monkeypatch: pytest.MonkeyPatch) -> None:
    captured_url = ""

    def fake_get(url: str, **_kwargs: object) -> httpx.Response:
        nonlocal captured_url
        captured_url = url
        return httpx.Response(200, json={"schema_version": "v1", "status": "ok"})

    doctor_module = importlib.import_module("vuln_proof_claw.cli.doctor")
    monkeypatch.setattr(doctor_module.httpx, "get", fake_get)
    settings = Settings(api=ApiConfig(host=WILDCARD_IPV4, port=9090))

    result = check_api(settings)

    assert result == DoctorCheck("api", True, "api_live")
    assert captured_url == "http://127.0.0.1:9090/api/v1/health/live"


@pytest.mark.parametrize(
    ("response", "expected_code"),
    [
        (httpx.Response(503), "api_unhealthy"),
        (httpx.Response(200, content=b"not-json"), "api_invalid_response"),
        (
            httpx.Response(200, json={"schema_version": "v2", "status": "ok"}),
            "api_invalid_response",
        ),
    ],
)
def test_api_check_rejects_unhealthy_or_invalid_contracts(
    monkeypatch: pytest.MonkeyPatch,
    response: httpx.Response,
    expected_code: str,
) -> None:
    doctor_module = importlib.import_module("vuln_proof_claw.cli.doctor")
    monkeypatch.setattr(doctor_module.httpx, "get", lambda *_args, **_kwargs: response)

    result = check_api(Settings())

    assert not result.ready
    assert result.code == expected_code


def test_api_check_handles_transport_failure(monkeypatch: pytest.MonkeyPatch) -> None:
    def fail(*_args: object, **_kwargs: object) -> httpx.Response:
        raise httpx.ConnectError("synthetic connection failure")

    doctor_module = importlib.import_module("vuln_proof_claw.cli.doctor")
    monkeypatch.setattr(doctor_module.httpx, "get", fail)

    assert check_api(Settings()).code == "api_unreachable"


def test_database_check_supports_ready_and_invalid_configuration() -> None:
    ready = Settings(database=DatabaseConfig(url=SecretStr("sqlite+pysqlite:///:memory:")))
    invalid = Settings(database=DatabaseConfig(url=SecretStr("not-a-database-url")))

    assert check_database(ready) == DoctorCheck("database", True, "database_ready")
    assert check_database(invalid) == DoctorCheck(
        "database",
        False,
        "database_configuration_invalid",
    )


def test_postgresql_doctor_url_has_bounded_connection_timeout() -> None:
    doctor_module = importlib.import_module("vuln_proof_claw.cli.doctor")

    database_url = doctor_module._doctor_database_url(Settings())

    assert database_url.query["connect_timeout"] == "3"


def test_docker_check_only_discovers_cli(monkeypatch: pytest.MonkeyPatch) -> None:
    doctor_module = importlib.import_module("vuln_proof_claw.cli.doctor")
    monkeypatch.setattr(doctor_module.shutil, "which", lambda _name: None)
    assert check_docker().code == "docker_cli_not_found"

    monkeypatch.setattr(doctor_module.shutil, "which", lambda _name: "docker")
    assert check_docker().code == "docker_cli_found"


def test_invalid_configuration_skips_dependent_checks_safely(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    doctor_module = importlib.import_module("vuln_proof_claw.cli.doctor")
    load_settings.cache_clear()
    monkeypatch.setenv("VULN_PROOF_CLAW_APP__ENVIRONMENT", "production")
    monkeypatch.setenv("VULN_PROOF_CLAW_APP__DEBUG", "true")
    monkeypatch.setattr(
        doctor_module,
        "check_docker",
        lambda: DoctorCheck("docker", False, "docker_cli_not_found"),
    )

    report = diagnose()
    load_settings.cache_clear()

    assert not report.ready
    assert report.checks[0].code == "configuration_invalid"
    assert report.checks[1].code == "skipped_invalid_configuration"
    assert report.checks[2].code == "skipped_invalid_configuration"
    serialized = str(report.as_dict())
    assert "VULN_PROOF_CLAW" not in serialized
