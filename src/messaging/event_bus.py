"""In-Memory AsyncIO EventBus implementation for ScamON Enterprise."""

from __future__ import annotations

import time
from collections.abc import Awaitable, Callable
from typing import Any, cast

from src.common.models import ComponentHealthDTO
from src.config.logging import get_logger
from src.container.di import Container
from src.events.base_event import BaseEvent
from src.interfaces.base import IModule
from src.interfaces.event_handler import IEventHandler
from src.interfaces.event_publisher import IEventPublisher
from src.interfaces.event_subscriber import IEventSubscriber
from src.messaging.dispatcher import EventDispatcher
from src.messaging.middleware import (
    ErrorHandlingMiddleware,
    EventMiddleware,
    LoggingMiddleware,
    MetricsMiddleware,
)
from src.messaging.subscriber import EventSubscriber
from src.registry.module_registry import ModuleRegistry

logger = get_logger("scamon.messaging.event_bus")


class InMemoryEventBus(IModule, IEventPublisher, IEventSubscriber):
    """In-memory AsyncIO Publish/Subscribe EventBus for Modular Monolith architecture."""

    def __init__(
        self,
        dead_letter_callback: Callable[[BaseEvent, str, Exception], Any] | None = None,
    ) -> None:
        self._subscriber = EventSubscriber()
        self._metrics_middleware = MetricsMiddleware()
        self._logging_middleware = LoggingMiddleware()
        self._error_middleware = ErrorHandlingMiddleware(
            dead_letter_callback=dead_letter_callback
        )
        self._dispatcher = EventDispatcher(
            middlewares=[
                self._logging_middleware,
                self._metrics_middleware,
                self._error_middleware,
            ]
        )
        self._running: bool = False

    @property
    def name(self) -> str:
        return "event_bus"

    @property
    def version(self) -> str:
        return "1.0.0"

    def add_middleware(self, middleware: EventMiddleware) -> None:
        """Add custom middleware to the event bus pipeline."""
        self._dispatcher.add_middleware(middleware)

    def subscribe[E: BaseEvent](
        self,
        event_type: type[E],
        handler: IEventHandler[E] | Callable[[E], Awaitable[None]],
    ) -> None:
        """Register a handler callback or object for a specific event type."""
        self._subscriber.subscribe(event_type, handler)
        logger.debug("Registered subscriber for event type: %s", event_type.__name__)

    def unsubscribe[E: BaseEvent](
        self,
        event_type: type[E],
        handler: IEventHandler[E] | Callable[[E], Awaitable[None]],
    ) -> None:
        """Remove a registered handler callback or object for an event type."""
        self._subscriber.unsubscribe(event_type, handler)

    async def publish(self, event: BaseEvent) -> None:
        """Publish an event to all registered bus subscribers asynchronously."""
        handlers = self._subscriber.get_handlers_for(event.__class__)
        await self._dispatcher.dispatch(event, handlers)

    async def initialize(self) -> None:
        """Lifecycle hook: Initialize event bus resources."""
        self._running = True
        logger.info("InMemoryEventBus initialized successfully.")

    async def shutdown(self) -> None:
        """Lifecycle hook: Orderly shutdown of event bus resources."""
        self._running = False
        logger.info("InMemoryEventBus shut down successfully.")

    async def health_check(self) -> ComponentHealthDTO:
        """Lifecycle hook: Return aggregated metrics and operational health."""
        start = time.perf_counter()
        status = "HEALTHY" if self._running else "UNHEALTHY"
        elapsed_ms = (time.perf_counter() - start) * 1000

        return ComponentHealthDTO(
            component_name=self.name,
            status=status,
            latency_ms=elapsed_ms,
            details={
                "published_count": self._metrics_middleware.published_count,
                "dispatched_count": self._metrics_middleware.dispatched_count,
                "error_count": self._metrics_middleware.error_count,
                "total_latency_ms": self._metrics_middleware.total_latency_ms,
                "running": self._running,
            },
        )


def register_event_bus(
    di_container: Container, module_registry: ModuleRegistry
) -> InMemoryEventBus:
    """Helper function to register InMemoryEventBus into DI Container and ModuleRegistry."""
    bus = InMemoryEventBus()
    di_container.register_instance(InMemoryEventBus, bus)
    di_container.register_instance(cast(type[Any], IEventPublisher), bus)
    di_container.register_instance(cast(type[Any], IEventSubscriber), bus)
    module_registry.register(bus)
    return bus
