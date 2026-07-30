"""Tests for structured, secret-safe logging."""

from __future__ import annotations

import json
from collections.abc import Generator
from typing import Any

import pytest
import structlog

from vuln_proof_claw.domain.identifiers import ContextIdentifiers
from vuln_proof_claw.observability.logging import (
    bind_log_context,
    clear_log_context,
    configure_logging,
)


@pytest.fixture(autouse=True)
def reset_logging_context() -> Generator[None, None, None]:
    clear_log_context()
    yield
    clear_log_context()
    structlog.reset_defaults()


def test_json_logging_binds_context_and_redacts_secrets(
    capsys: pytest.CaptureFixture[str],
) -> None:
    configure_logging(log_format="json")
    bind_log_context(
        ContextIdentifiers(
            request_id="request-1",
            project_id="project-1",
            engagement_id="engagement-1",
            flow_id="flow-1",
            task_id="task-1",
            action_id="action-1",
            worker_id="worker-1",
        )
    )

    structlog.get_logger().info(
        "worker_started",
        authorization="Bearer header.payload.signature",
        safe="visible",
    )

    event: dict[str, Any] = json.loads(capsys.readouterr().out)
    assert event["event"] == "worker_started"
    assert event["request_id"] == "request-1"
    assert event["action_id"] == "action-1"
    assert event["worker_id"] == "worker-1"
    assert event["authorization"] == "[REDACTED]"
    assert event["safe"] == "visible"
    assert "header.payload.signature" not in repr(event)


def test_human_logging_is_readable(capsys: pytest.CaptureFixture[str]) -> None:
    configure_logging(log_format="human", level="WARNING")

    logger = structlog.get_logger()
    logger.info("hidden_event")
    logger.warning("visible_event", action_id="action-1")

    output = capsys.readouterr().out
    assert "hidden_event" not in output
    assert "visible_event" in output
    assert "action-1" in output


def test_invalid_log_level_is_rejected() -> None:
    with pytest.raises(ValueError, match="unsupported log level"):
        configure_logging(level="VERBOSE")
