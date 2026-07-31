"""Command-line module entry point."""

from vuln_proof_claw.cli.app import app, main

__all__ = ["app", "main"]


if __name__ == "__main__":
    main()
