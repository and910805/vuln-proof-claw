"""Secret-safe structured logging configuration."""

from __future__ import annotations

import logging
import sys
from collections.abc import MutableMapping
from typing import Any, Literal, cast

import structlog
from structlog.contextvars import bind_contextvars, clear_contextvars, merge_contextvars
from structlog.typing import EventDict, Processor

from vuln_proof_claw.config.redaction import redact
from vuln_proof_claw.domain.identifiers import ContextIdentifiers


def redact_event(
    _logger: Any,
    _method_name: str,
    event_dict: MutableMapping[str, Any],
) -> EventDict:
    """Redact protected data before a log event is serialized."""
    return cast("EventDict", redact(event_dict))


def configure_logging(
    *,
    log_format: Literal["human", "json"] = "human",
    level: str = "INFO",
) -> None:
    """Configure standard-library and structlog output for the process."""
    numeric_level = logging.getLevelNamesMapping().get(level.upper())
    if numeric_level is None:
        msg = f"unsupported log level: {level}"
        raise ValueError(msg)

    shared_processors: list[Processor] = [
        merge_contextvars,
        structlog.processors.add_log_level,
        structlog.processors.TimeStamper(fmt="iso", utc=True),
        structlog.processors.StackInfoRenderer(),
        structlog.processors.format_exc_info,
        redact_event,
    ]
    renderer: Processor
    if log_format == "json":
        renderer = structlog.processors.JSONRenderer(sort_keys=True)
    else:
        renderer = structlog.dev.ConsoleRenderer(colors=False)

    logging.basicConfig(format="%(message)s", level=numeric_level, stream=sys.stdout, force=True)
    structlog.configure(
        processors=[*shared_processors, renderer],
        wrapper_class=structlog.make_filtering_bound_logger(numeric_level),
        logger_factory=structlog.stdlib.LoggerFactory(),
        cache_logger_on_first_use=True,
    )


def bind_log_context(identifiers: ContextIdentifiers) -> None:
    """Bind correlation identifiers to the current async/thread context."""
    bind_contextvars(**identifiers.as_log_context())


def clear_log_context() -> None:
    """Clear correlation identifiers at a request or task boundary."""
    clear_contextvars()
