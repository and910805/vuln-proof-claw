"""REST control-plane API."""

from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from vuln_proof_claw.api.app import create_app

__all__ = ["create_app"]


def __getattr__(name: str) -> Any:
    """Resolve ``create_app`` on first use instead of at import time.

    ``reporting.bundle`` imports a single schema from ``api.schemas.reports``.
    Importing that submodule runs this package, and eagerly building the app
    here pulled in every route - one of which imports ``reporting.bundle``
    while it is still initialising. That cycle broke every command-line entry
    point while leaving the test suite green, because the tests happen to
    import the API before the CLI.
    """
    if name == "create_app":
        from vuln_proof_claw.api.app import create_app  # noqa: PLC0415 - deferred by design

        return create_app
    message = f"module {__name__!r} has no attribute {name!r}"
    raise AttributeError(message)
