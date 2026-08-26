"""Tests that the installed command-line entry point actually starts.

These run the CLI in a fresh interpreter on purpose. Import-order defects such
as a circular import between the API package and the reporting module cannot be
reproduced in-process, because by then the test session has already imported
the modules in a different order.
"""

from __future__ import annotations

import subprocess
import sys

TIMEOUT_SECONDS = 60


def run_cli(*arguments: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(  # noqa: S603 - argv is built here, not from input
        [sys.executable, "-m", "vuln_proof_claw", *arguments],
        capture_output=True,
        text=True,
        timeout=TIMEOUT_SECONDS,
        check=False,
    )


def test_version_starts_without_an_import_error() -> None:
    completed = run_cli("--version")
    assert "ImportError" not in completed.stderr
    assert "circular import" not in completed.stderr
    assert completed.returncode == 0


def test_help_lists_every_command() -> None:
    completed = run_cli("--help")
    assert completed.returncode == 0
    for command in ("doctor", "preflight", "verify-bundle"):
        assert command in completed.stdout


def test_preflight_reports_json_even_when_tools_are_missing() -> None:
    completed = run_cli("preflight", "--json")
    assert "ImportError" not in completed.stderr
    # Exit code 1 is correct on a machine without the scanners installed; the
    # point is that it produced a report rather than failing to start.
    assert completed.returncode in (0, 1)
    assert '"schema_version":"v1"' in completed.stdout


def test_importing_a_schema_module_does_not_build_the_app() -> None:
    completed = subprocess.run(
        [
            sys.executable,
            "-c",
            "import vuln_proof_claw.reporting.bundle; import sys; "
            "print('api.app' in sys.modules)",
        ],
        capture_output=True,
        text=True,
        timeout=TIMEOUT_SECONDS,
        check=False,
    )
    assert completed.returncode == 0, completed.stderr
    assert completed.stdout.strip() == "False"
