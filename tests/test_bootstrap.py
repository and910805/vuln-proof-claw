"""Bootstrap tests for package, CLI, and release-version consistency."""

import json
import subprocess
import sys
import tomllib
from pathlib import Path

import pytest
from typer.testing import CliRunner

from vuln_proof_claw import __version__
from vuln_proof_claw.__main__ import app

runner = CliRunner()


def test_version_is_pep440_compatible() -> None:
    assert __version__ == "0.7.1"


def test_release_version_is_consistent() -> None:
    project_root = Path(__file__).parents[1]
    release_version = (project_root / "VERSION").read_text(encoding="utf-8").strip()
    pyproject = tomllib.loads((project_root / "pyproject.toml").read_text(encoding="utf-8"))
    web_package = json.loads((project_root / "web" / "package.json").read_text(encoding="utf-8"))

    assert release_version == __version__
    assert pyproject["project"]["version"] == release_version
    assert web_package["version"] == release_version


def test_cli_help() -> None:
    result = runner.invoke(app, ["--help"])

    assert result.exit_code == 0
    assert "Evidence-driven autonomous Web and API security testing platform." in result.output


def test_cli_version() -> None:
    result = runner.invoke(app, ["--version"])

    assert result.exit_code == 0
    assert result.output.strip() == __version__


@pytest.mark.parametrize(
    "module",
    [
        "vuln_proof_claw.config.identities",
        "vuln_proof_claw.config.engagement",
        "vuln_proof_claw.policy.scope",
        "vuln_proof_claw.domain.autonomous",
        "vuln_proof_claw.reporting.bundle",
    ],
)
def test_a_lower_layer_imports_on_its_own(module: str) -> None:
    """Each of these must import in a fresh interpreter with nothing else loaded.

    A circular import between layers stays invisible while something always happens to
    load the upper one first. It surfaces the moment a script imports the lower module
    directly — which is how config.identities was found to pull in the agent package,
    whose __init__ reaches back into config.
    """
    result = subprocess.run(  # noqa: S603 - fixed interpreter, parametrised module name
        [sys.executable, "-c", f"import {module}"],
        capture_output=True,
        text=True,
        check=False,
    )

    assert result.returncode == 0, result.stderr
