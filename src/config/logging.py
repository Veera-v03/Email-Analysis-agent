"""Production logging framework for ScamON Enterprise."""

from __future__ import annotations

import contextvars
import json
import logging
import sys
from datetime import UTC, datetime
from typing import Any

from src.common.constants import LogFormat
from src.config.settings import get_settings

# Contextual variables for distributed tracing and multi-tenant isolation
trace_id_var: contextvars.ContextVar[str | None] = contextvars.ContextVar(
    "trace_id", default=None
)
tenant_id_var: contextvars.ContextVar[str | None] = contextvars.ContextVar(
    "tenant_id", default=None
)


def set_log_context(trace_id: str | None = None, tenant_id: str | None = None) -> None:
    """Set contextual log identifiers for the current execution context."""
    if trace_id is not None:
        trace_id_var.set(trace_id)
    if tenant_id is not None:
        tenant_id_var.set(tenant_id)


def clear_log_context() -> None:
    """Clear execution context variables."""
    trace_id_var.set(None)
    tenant_id_var.set(None)


class JSONFormatter(logging.Formatter):
    """Production JSON log formatter enforcing structured telemetry format."""

    def format(self, record: logging.LogRecord) -> str:
        log_object: dict[str, Any] = {
            "timestamp": datetime.now(UTC).isoformat(),
            "level": record.levelname,
            "logger": record.name,
            "message": record.getMessage(),
            "environment": get_settings().environment.value,
        }

        # Include tracing context if present
        trace_id = trace_id_var.get()
        if trace_id:
            log_object["trace_id"] = trace_id

        tenant_id = tenant_id_var.get()
        if tenant_id:
            log_object["tenant_id"] = tenant_id

        if record.exc_info and record.exc_text:
            log_object["exception"] = record.exc_text

        # Include extra attributes attached to record
        if hasattr(record, "extra_fields") and isinstance(record.extra_fields, dict):
            log_object.update(record.extra_fields)

        return json.dumps(log_object)


def setup_logging() -> None:
    """Initialize system-wide logging configuration based on application settings."""
    settings = get_settings()
    log_level = getattr(logging, settings.log_level.upper(), logging.INFO)

    root_logger = logging.getLogger()
    root_logger.setLevel(log_level)

    # Clear existing handlers to prevent duplicate output
    root_logger.handlers.clear()

    stream_handler = logging.StreamHandler(sys.stdout)
    stream_handler.setLevel(log_level)

    if settings.log_format == LogFormat.JSON.value:
        stream_handler.setFormatter(JSONFormatter())
    else:
        fmt = "%(asctime)s [%(levelname)s] %(name)s: %(message)s"
        stream_handler.setFormatter(logging.Formatter(fmt))

    root_logger.addHandler(stream_handler)


def get_logger(name: str) -> logging.Logger:
    """Obtain a named logger configured with system defaults."""
    return logging.getLogger(name)
