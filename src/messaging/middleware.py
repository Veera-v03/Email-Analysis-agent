"""Event bus middleware pipeline components for ScamON Enterprise."""

from __future__ import annotations

import time
from abc import ABC, abstractmethod
from collections.abc import Callable
from typing import Any

from src.config.logging import clear_log_context, get_logger, set_log_context
from src.events.base_event import BaseEvent

logger = get_logger("scamon.messaging.middleware")


class EventMiddleware(ABC):
    """Abstract base middleware interface for processing events on dispatch."""

    @abstractmethod
    async def before_dispatch(self, event: BaseEvent) -> None:
        """Executed before event is dispatched to subscribers."""
        ...

    @abstractmethod
    async def after_dispatch(self, event: BaseEvent, elapsed_ms: float) -> None:
        """Executed after event is successfully processed by subscribers."""
        ...

    @abstractmethod
    async def on_error(
        self, event: BaseEvent, subscriber_name: str, error: Exception
    ) -> None:
        """Executed when a subscriber handler raises an exception."""
        ...


class LoggingMiddleware(EventMiddleware):
    """Middleware enforcing structured logging and contextvars tracing propagation."""

    async def before_dispatch(self, event: BaseEvent) -> None:
        tenant_str = str(event.tenant_id) if hasattr(event, "tenant_id") else None
        set_log_context(trace_id=str(event.correlation_id), tenant_id=tenant_str)
        logger.info(
            "Event [%s] correlation_id=%s dispatched",
            event.event_type,
            event.correlation_id,
        )

    async def after_dispatch(self, event: BaseEvent, elapsed_ms: float) -> None:
        logger.info(
            "Event [%s] correlation_id=%s processed successfully in %.2fms",
            event.event_type,
            event.correlation_id,
            elapsed_ms,
        )
        clear_log_context()

    async def on_error(
        self, event: BaseEvent, subscriber_name: str, error: Exception
    ) -> None:
        logger.error(
            "Event [%s] correlation_id=%s failed in subscriber '%s': %s",
            event.event_type,
            event.correlation_id,
            subscriber_name,
            error,
        )
        clear_log_context()


class MetricsMiddleware(EventMiddleware):
    """Middleware collecting operational metrics for event bus health checking."""

    def __init__(self) -> None:
        self.published_count: int = 0
        self.dispatched_count: int = 0
        self.error_count: int = 0
        self.total_latency_ms: float = 0.0

    async def before_dispatch(self, event: BaseEvent) -> None:
        self.published_count += 1

    async def after_dispatch(self, event: BaseEvent, elapsed_ms: float) -> None:
        self.dispatched_count += 1
        self.total_latency_ms += elapsed_ms

    async def on_error(
        self, event: BaseEvent, subscriber_name: str, error: Exception
    ) -> None:
        self.error_count += 1


class ErrorHandlingMiddleware(EventMiddleware):
    """Middleware isolating subscriber exceptions and invoking dead-letter callback."""

    def __init__(
        self,
        dead_letter_callback: Callable[[BaseEvent, str, Exception], Any] | None = None,
    ) -> None:
        self.dead_letter_callback = dead_letter_callback

    async def before_dispatch(self, event: BaseEvent) -> None:
        pass

    async def after_dispatch(self, event: BaseEvent, elapsed_ms: float) -> None:
        pass

    async def on_error(
        self, event: BaseEvent, subscriber_name: str, error: Exception
    ) -> None:
        if self.dead_letter_callback:
            try:
                res = self.dead_letter_callback(event, subscriber_name, error)
                if hasattr(res, "__await__"):
                    await res
            except Exception as dlq_err:
                logger.error("Dead-letter callback failed: %s", dlq_err)
