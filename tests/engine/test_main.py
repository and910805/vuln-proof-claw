"""Engine service process entry-point tests."""

from __future__ import annotations

import pytest
from pydantic import SecretStr

from vuln_proof_claw.config.models import EngineServerConfig
from vuln_proof_claw.config.settings import Settings
from vuln_proof_claw.engine import __main__ as engine_main


def test_engine_process_refuses_to_start_while_disabled(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(engine_main, "load_settings", Settings)

    with pytest.raises(SystemExit, match="engine_server_disabled"):
        engine_main.main()


def test_engine_process_uses_the_restricted_listener_configuration(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    settings = Settings(
        engine_server=EngineServerConfig(
            enabled=True,
            host="::1",
            port=9081,
            token=SecretStr("e" * 32),
        )
    )
    configured_logs: list[tuple[str, str]] = []
    server_calls: list[dict[str, object]] = []

    monkeypatch.setattr(engine_main, "load_settings", lambda: settings)
    monkeypatch.setattr(
        engine_main,
        "configure_logging",
        lambda *, log_format, level: configured_logs.append((log_format, level)),
    )

    def run_server(app: object, **options: object) -> None:
        server_calls.append({"app": app, **options})

    monkeypatch.setattr("vuln_proof_claw.engine.__main__.uvicorn.run", run_server)

    engine_main.main()

    assert configured_logs == [(settings.logging.format, settings.logging.level)]
    assert server_calls[0]["host"] == "::1"
    assert server_calls[0]["port"] == 9081
    assert server_calls[0]["access_log"] is False
    assert callable(server_calls[0]["app"])
