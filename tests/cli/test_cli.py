"""Tests for top-level CLI contracts."""

from __future__ import annotations

import importlib
import json
from pathlib import Path

import pytest
from typer.testing import CliRunner

from vuln_proof_claw import __version__
from vuln_proof_claw.cli.app import app
from vuln_proof_claw.cli.doctor import DoctorCheck, DoctorReport
from vuln_proof_claw.reporting.bundle import BundleVerification

runner = CliRunner()


def test_help_lists_doctor_command() -> None:
    result = runner.invoke(app, ["--help"])

    assert result.exit_code == 0
    assert "Evidence-driven autonomous Web and API security testing platform." in result.output
    assert "doctor" in result.output
    assert "verify-bundle" in result.output


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


def test_verify_bundle_has_machine_readable_success(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    cli_module = importlib.import_module("vuln_proof_claw.cli.app")
    bundle = tmp_path / "bundle.zip"
    bundle.write_bytes(b"fixture")
    monkeypatch.setattr(
        cli_module,
        "verify_disclosure_bundle",
        lambda _path: BundleVerification(True, (), "engagement-1", 5, "a" * 64),
    )

    result = runner.invoke(app, ["verify-bundle", str(bundle), "--json"])

    assert result.exit_code == 0
    assert json.loads(result.output)["valid"] is True


def test_verify_bundle_returns_nonzero_for_tampering(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    cli_module = importlib.import_module("vuln_proof_claw.cli.app")
    bundle = tmp_path / "bundle.zip"
    bundle.write_bytes(b"fixture")
    monkeypatch.setattr(
        cli_module,
        "verify_disclosure_bundle",
        lambda _path: BundleVerification(False, ("digest_mismatch:report.md",)),
    )

    result = runner.invoke(app, ["verify-bundle", str(bundle)])

    assert result.exit_code == 1
    assert "digest_mismatch:report.md" in result.output
