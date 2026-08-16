"""Browser worker login logic tests using an injected engine (no browser)."""

from __future__ import annotations

import json
from datetime import UTC, datetime

from vuln_proof_claw.execution.browser_worker import (
    LoginError,
    LoginResult,
    LoginTimeoutError,
    run_login,
)
from vuln_proof_claw.execution.session_envelope import LoginInstruction

NOW = datetime(2026, 8, 17, 12, 0, tzinfo=UTC)


def _instruction() -> LoginInstruction:
    return LoginInstruction(
        url="http://target:8080/login",
        username="operator",
        password="hunter2",
        username_selector="#username",
        password_selector="#password",
        submit_selector="#submit",
        success_url_substring="/home",
    )


def test_successful_login_captures_storage_state_and_key_names() -> None:
    storage_state: dict[str, object] = {
        "cookies": [{"name": "sessionid", "value": "SECRET-COOKIE", "domain": "target"}],
        "origins": [
            {
                "origin": "http://target:8080",
                "localStorage": [{"name": "token", "value": "SECRET-TOKEN"}],
            }
        ],
    }

    def engine(instruction: LoginInstruction) -> LoginResult:
        assert instruction.url == "http://target:8080/login"
        return "http://target:8080/home", storage_state

    envelope = run_login(_instruction(), engine, now=lambda: NOW)

    assert envelope.status == "succeeded"
    assert envelope.final_url == "http://target:8080/home"
    assert envelope.cookie_names == ("sessionid",)
    assert envelope.storage_keys == ("token",)
    assert json.loads(envelope.storage_state_json or "") == storage_state


def test_login_timeout_and_failure_map_to_safe_codes() -> None:
    def timing_out(instruction: LoginInstruction) -> LoginResult:
        raise LoginTimeoutError("deadline")

    def failing(instruction: LoginInstruction) -> LoginResult:
        raise LoginError("selector not found")

    timed_out = run_login(_instruction(), timing_out, now=lambda: NOW)
    failed = run_login(_instruction(), failing, now=lambda: NOW)

    assert timed_out.status == "failed"
    assert timed_out.error_code == "login_timed_out"
    assert failed.status == "failed"
    assert failed.error_code == "login_failed"


def test_storage_state_without_origins_still_captures_cookies() -> None:
    def engine(instruction: LoginInstruction) -> LoginResult:
        return "http://target:8080/home", {"cookies": [{"name": "sid", "value": "x"}]}

    envelope = run_login(_instruction(), engine, now=lambda: NOW)

    assert envelope.cookie_names == ("sid",)
    assert envelope.storage_keys == ()
