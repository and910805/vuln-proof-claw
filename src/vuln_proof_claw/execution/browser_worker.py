"""Disposable browser worker: perform one form login and capture its session.

The worker runs inside an isolated, egress-restricted container. It reads a
single :class:`LoginInstruction` from the environment, drives a headless browser
through the login, and writes one :class:`SessionCaptureEnvelope` describing the
resulting storage state. Credentials are used only to log in; only the captured
storage state (cookies and per-origin storage) leaves the worker.
"""

from __future__ import annotations

import json
import os
import sys
from collections.abc import Callable
from datetime import UTC, datetime

from pydantic import ValidationError

from vuln_proof_claw.execution.session_envelope import (
    SESSION_REQUEST_ENV,
    LoginInstruction,
    SessionCaptureEnvelope,
)

LoginResult = tuple[str, dict[str, object]]
LoginEngine = Callable[[LoginInstruction], LoginResult]


class LoginTimeoutError(Exception):
    """Raised when the login exceeds its deadline."""


class LoginError(Exception):
    """Raised for any other failure while driving the browser."""


def _cookie_names(storage_state: dict[str, object]) -> tuple[str, ...]:
    cookies = storage_state.get("cookies", [])
    if not isinstance(cookies, list):
        return ()
    return tuple(
        str(cookie["name"])
        for cookie in cookies
        if isinstance(cookie, dict) and "name" in cookie
    )


def _storage_keys(storage_state: dict[str, object]) -> tuple[str, ...]:
    origins = storage_state.get("origins", [])
    if not isinstance(origins, list):
        return ()
    keys: list[str] = []
    for origin in origins:
        if not isinstance(origin, dict):
            continue
        local_storage = origin.get("localStorage") or []
        if not isinstance(local_storage, list):
            continue
        keys.extend(
            str(item["name"])
            for item in local_storage
            if isinstance(item, dict) and "name" in item
        )
    return tuple(keys)


def run_login(
    instruction: LoginInstruction,
    engine: LoginEngine,
    *,
    now: Callable[[], datetime] = lambda: datetime.now(UTC),
) -> SessionCaptureEnvelope:
    """Drive the login through ``engine`` and return a capture envelope."""
    started = now()
    try:
        final_url, storage_state = engine(instruction)
    except LoginTimeoutError:
        return SessionCaptureEnvelope(status="failed", error_code="login_timed_out")
    except LoginError:
        return SessionCaptureEnvelope(status="failed", error_code="login_failed")

    duration_ms = int((now() - started).total_seconds() * 1000)
    return SessionCaptureEnvelope(
        status="succeeded",
        final_url=final_url,
        storage_state_json=json.dumps(storage_state, sort_keys=True, separators=(",", ":")),
        cookie_names=_cookie_names(storage_state),
        storage_keys=_storage_keys(storage_state),
        duration_ms=duration_ms,
    )


def _playwright_login(instruction: LoginInstruction) -> LoginResult:
    # Imported lazily: Playwright ships only in the browser image, not the package.
    from playwright.sync_api import TimeoutError as PlaywrightTimeoutError  # noqa: PLC0415
    from playwright.sync_api import sync_playwright  # noqa: PLC0415

    try:
        with sync_playwright() as playwright:
            browser = playwright.chromium.launch(
                args=["--no-sandbox", "--disable-dev-shm-usage"],
            )
            try:
                context = browser.new_context()
                page = context.new_page()
                page.set_default_timeout(instruction.timeout_seconds * 1000)
                page.goto(instruction.url)
                page.fill(instruction.username_selector, instruction.username)
                page.fill(instruction.password_selector, instruction.password)
                page.click(instruction.submit_selector)
                if instruction.success_url_substring:
                    page.wait_for_url(f"**{instruction.success_url_substring}**")
                else:
                    page.wait_for_load_state("networkidle")
                storage_state = dict(context.storage_state())
                final_url = page.url
            finally:
                browser.close()
    except PlaywrightTimeoutError as error:
        raise LoginTimeoutError(str(error)) from error
    except Exception as error:
        raise LoginError(str(error)) from error
    return final_url, storage_state


def main() -> None:
    """Read the instruction, perform the login, and emit the capture envelope."""
    raw = os.environ.get(SESSION_REQUEST_ENV, "")
    try:
        instruction = LoginInstruction.model_validate_json(raw)
    except ValidationError:
        sys.stdout.write(
            SessionCaptureEnvelope(status="failed", error_code="worker_error").model_dump_json()
            + "\n"
        )
        sys.stdout.flush()
        raise SystemExit(2) from None

    envelope = run_login(instruction, _playwright_login)
    sys.stdout.write(envelope.model_dump_json() + "\n")
    sys.stdout.flush()


if __name__ == "__main__":
    main()
