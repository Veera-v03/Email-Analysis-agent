"""Reusable application logging configuration."""

from __future__ import annotations

import logging
from typing import Literal

LogLevel = Literal["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"]
LOG_FORMAT = "%(asctime)s | %(levelname)-8s | %(name)s | %(message)s"
DATE_FORMAT = "%Y-%m-%dT%H:%M:%S%z"


def configure_logging(log_level: LogLevel) -> None:
    """Configure idempotent console logging for the application.

    Args:
        log_level: Minimum severity emitted by the root logger.
    """
    logging.basicConfig(
        level=getattr(logging, log_level),
        format=LOG_FORMAT,
        datefmt=DATE_FORMAT,
        force=True,
    )


def get_logger(name: str) -> logging.Logger:
    """Return a named logger for a module or application component."""
    return logging.getLogger(name)
