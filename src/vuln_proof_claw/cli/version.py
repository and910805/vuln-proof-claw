"""CLI version output."""

from __future__ import annotations

import typer

from vuln_proof_claw import __version__


def print_version() -> None:
    """Print the installed package version."""
    typer.echo(__version__)
