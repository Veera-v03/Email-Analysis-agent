"""Module 20 lifecycle registration and health check manager implementation."""

from __future__ import annotations

from typing import Any

from src.common.models import ComponentHealthDTO
from src.config.logging import get_logger
from src.container.di import Container
from src.interfaces.base import IHealthCheckable, IModule
from src.interfaces.event_subscriber import IEventSubscriber
from src.notifications.engine import NotificationEngine
from src.notifications.subscribers import NotificationEventSubscriber
from src.registry.module_registry import ModuleRegistry

logger = get_logger("scamon.notifications.module")


class NotificationModule(IModule, IHealthCheckable):
    """Module 20 Enterprise SOC Alerting and Multi-Channel Notification Lifecycle Manager."""

    def __init__(
        self,
        engine: NotificationEngine | None = None,
        di_container: Container | None = None,
    ) -> None:
        self.engine = engine or NotificationEngine()
        self.container = di_container or Container()
        self.subscriber: NotificationEventSubscriber | None = None
        self._is_initialized = False

    @property
    def name(self) -> str:
        return "notifications"

    @property
    def version(self) -> str:
        return "1.0.0"

    async def initialize(self) -> None:
        """Initialize NotificationModule resources, DI bindings, and event subscriptions."""
        if self._is_initialized:
            return

        logger.info("Initializing NotificationModule v1.0.0...")

        # If EventSubscriber is available in DI container, wire up event subscriptions
        try:
            from src.interfaces.event_publisher import IEventPublisher

            event_subscriber = self.container.resolve_optional(IEventSubscriber)
            event_publisher = self.container.resolve_optional(IEventPublisher)

            if event_subscriber:
                self.subscriber = NotificationEventSubscriber(
                    engine=self.engine,
                    publisher=event_publisher,
                )
                self.subscriber.subscribe_to_bus(event_subscriber)
                logger.info("NotificationModule subscribed to EventBus security events.")
        except Exception as exc:
            logger.warning("EventBus subscription during notification module init: %s", exc)

        self._is_initialized = True
        logger.info("NotificationModule initialized successfully.")

    async def shutdown(self) -> None:
        """Shutdown NotificationModule cleanly."""
        logger.info("Shutting down NotificationModule...")
        self._is_initialized = False
        logger.info("NotificationModule shutdown complete.")

    async def health_check(self) -> ComponentHealthDTO:
        """Return operational health status and dispatch telemetry."""
        metrics = self.engine.get_metrics()
        return ComponentHealthDTO(
            component_name=self.name,
            status="HEALTHY" if self._is_initialized else "DEGRADED",
            details={
                "initialized": self._is_initialized,
                "version": self.version,
                **metrics,
            },
        )


def register_notification_module(
    container: Container, registry: ModuleRegistry
) -> NotificationModule:
    """Helper function registering NotificationModule with global DI Container and ModuleRegistry."""
    engine = NotificationEngine()
    mod = NotificationModule(engine=engine, di_container=container)

    container.register_instance(NotificationEngine, engine)
    container.register_instance(NotificationModule, mod)
    registry.register(mod)

    return mod
