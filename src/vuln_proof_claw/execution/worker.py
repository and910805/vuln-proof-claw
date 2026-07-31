"""Phase 0 worker-image entry point."""

from __future__ import annotations

import json


def main() -> None:
    """Fail closed because target-facing execution is not implemented in Phase 0."""
    print(  # noqa: T201 - worker protocol response is intentionally written to stdout
        json.dumps(
            {
                "component": "worker",
                "state": "disabled",
                "error_code": "worker_execution_not_implemented",
            },
            separators=(",", ":"),
            sort_keys=True,
        )
    )
    raise SystemExit(2)


if __name__ == "__main__":
    main()
