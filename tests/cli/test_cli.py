"""Tests for top-level CLI contracts."""

from __future__ import annotations

import importlib
import json

import pytest
from typer.testing import CliRunner

from vuln_proof_claw import __version__
from vuln_proof_claw.cli.app import app
from vuln_proof_claw.cli.doctor import DoctorCheck, DoctorReport

runner = CliRunner()


def test_help_lists_doctor_command() -> None:
    result = runner.invoke(app, ["--help"])

    assert result.exit_code == 0
    assert "Evidence-driven autonomous Web and API security testing platform." in result.output
    assert "doctor" in result.output


def test_version_is_available_as_eager_option() -> None:
    result = runner.invoke(app, ["--version"])

    assert result.exit_code == 0
    assert result.output.strip() == __version__


def test_doctor_json_has_stable_contract(monkeypatch: pytest.MonkeyPatch) -> None:
    cli_module = importlib.import_module("vuln_proof_claw.cli.app")
    report = DoctorReport(
        checks=(
            DoctorCheck("configuration", True, "configuration_valid"),
            DoctorCheck("api", True, "api_live"),
            DoctorCheck("database", True, "database_ready"),
            DoctorCheck("docker", True, "docker_cli_found"),
        )
    )
    monkeypatch.setattr(cli_module, "diagnose", lambda: report)

    result = runner.invoke(app, ["doctor", "--json"])

    assert result.exit_code == 0
    payload = json.loads(result.output)
    assert payload["schema_version"] == "v1"
    assert payload["status"] == "ready"
    assert len(payload["checks"]) == 4


def test_doctor_failure_is_nonzero_and_credential_free(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    cli_module = importlib.import_module("vuln_proof_claw.cli.app")
    report = DoctorReport(
        checks=(
            DoctorCheck("configuration", True, "configuration_valid"),
            DoctorCheck("api", False, "api_unreachable"),
            DoctorCheck("database", False, "database_unavailable"),
            DoctorCheck("docker", False, "docker_cli_not_found"),
        )
    )
    monkeypatch.setattr(cli_module, "diagnose", lambda: report)

    result = runner.invoke(app, ["doctor"])

    assert result.exit_code == 1
    assert "[failed] database: database_unavailable" in result.output
    assert "password" not in result.output.lower()
    assert "postgresql://" not in result.output
