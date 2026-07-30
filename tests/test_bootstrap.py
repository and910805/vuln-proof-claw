"""Bootstrap tests for the package and CLI."""

from typer.testing import CliRunner

from vuln_proof_claw import __version__
from vuln_proof_claw.__main__ import app

runner = CliRunner()


def test_version_is_pep440_compatible() -> None:
    assert __version__ == "0.0.1"


def test_cli_help() -> None:
    result = runner.invoke(app, ["--help"])

    assert result.exit_code == 0
    assert "Evidence-driven autonomous Web and API security testing platform." in result.output


def test_cli_version() -> None:
    result = runner.invoke(app, ["--version"])

    assert result.exit_code == 0
    assert result.output.strip() == __version__
