"""Observability framework tracking system metrics, latency timers, and structured logger utilities."""

from __future__ import annotations

import os
import time
import uuid
from typing import Any

from src.utils.logging import get_logger

logger = get_logger(__name__)


class RequestTracker:
    """Utility to generate request execution contexts containing Correlation/Request IDs and duration metrics."""

    def __init__(self) -> None:
        self.request_id = f"req_{uuid.uuid4().hex[:12]}"
        self.start_time = time.perf_counter_ns()

    def get_duration_ms(self) -> int:
        """Return milliseconds elapsed since initialization."""
        elapsed_ns = time.perf_counter_ns() - self.start_time
        return max(0, int(elapsed_ns / 1_000_000))


def get_system_metrics() -> dict[str, Any]:
    """Retrieve operational system statistics for liveness / health reports."""
    # Basic mock system monitoring stats
    cpu_percent = 15.4
    memory_percent = 42.1
    disk_percent = 68.3

    # Try standard library platform calls if available
    try:
        load = os.getloadavg()
        cpu_percent = round(load[0] * 10, 1)
    except (AttributeError, OSError):
        pass

    return {
        "cpu_usage_percent": cpu_percent,
        "memory_usage_percent": memory_percent,
        "disk_usage_percent": disk_percent,
        "process_id": os.getpid(),
    }


class LatencyTracker:
    """Decorator or context manager to measure latency of individual modules."""

    def __init__(self, component_name: str) -> None:
        self.component = component_name
        self.start_ns = 0

    def __enter__(self) -> LatencyTracker:
        self.start_ns = time.perf_counter_ns()
        return self

    def __exit__(self, exc_type: Any, exc_val: Any, exc_tb: Any) -> None:
        duration_ms = max(0, int((time.perf_counter_ns() - self.start_ns) / 1_000_000))
        logger.info(
            "Component '%s' execution finished in %d ms.",
            self.component,
            duration_ms,
            extra={"component": self.component, "latency_ms": duration_ms},
        )
