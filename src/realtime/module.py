"""Module 22 Real-time SOC event stream lifecycle manager and DI registration."""

from __future__ import annotations

from typing import Any

from src.common.models import ComponentHealthDTO
from src.config.enterprise_config import settings
from src.config.logging import get_logger
from src.container.di import Container
from src.interfaces.base import IHealthCheckable, IModule
from src.interfaces.event_publisher import IEventPublisher
from src.realtime.broadcaster import SOCEventBroadcaster, get_event_broadcaster
from src.registry.module_registry import ModuleRegistry

logger = get_logger("scamon.realtime.module")


class RealtimeModule(IModule, IHealthCheckable):
    """Module 22 Real-Time SOC Event Stream Lifecycle Manager."""

    def __init__(
        self,
        broadcaster: SOCEventBroadcaster | None = None,
        di_container: Container | None = None,
    ) -> None:
        self.container = di_container or Container()
        self.broadcaster = broadcaster or get_event_broadcaster()
        self._is_initialized = False

    @property
    def name(self) -> str:
        return "realtime"

    @property
    def version(self) -> str:
        return "1.0.0"

    async def initialize(self) -> None:
        """Initialize RealtimeModule, subscribe to EventBus, and launch heartbeat worker."""
        if self._is_initialized:
            return

        logger.info("Initializing RealtimeModule v1.0.0...")

        # 1. Wire EventBus / Publisher subscription if available
        try:
            if self.container.has(IEventPublisher):
                bus = self.container.resolve(IEventPublisher)
                self.broadcaster.subscribe_to_event_bus(bus)
                logger.info("RealtimeModule subscribed broadcaster to EventBus.")
        except Exception as exc:
            logger.warning("Failed to subscribe broadcaster to EventBus: %s", exc)

        # 2. Auto-start broadcaster if enabled in configuration
        if settings.realtime_enabled:
            self.broadcaster.start()

        self._is_initialized = True
        logger.info("RealtimeModule initialized successfully.")

    async def shutdown(self) -> None:
        """Gracefully shutdown broadcaster and close all active client WebSocket connections."""
        logger.info("Shutting down RealtimeModule...")
        await self.broadcaster.stop()
        self._is_initialized = False
        logger.info("RealtimeModule shutdown complete.")

    async def health_check(self) -> ComponentHealthDTO:
        """Return operational health status and connection metrics."""
        stats = self.broadcaster.get_stats()
        overall_status = "HEALTHY" if self._is_initialized else "DEGRADED"

        return ComponentHealthDTO(
            component_name=self.name,
            status=overall_status,
            details={
                "initialized": self._is_initialized,
                "version": self.version,
                **stats,
            },
        )


def register_realtime_module(
    container: Container,
    registry: ModuleRegistry | None = None,
) -> RealtimeModule:
    """Helper registering RealtimeModule and SOCEventBroadcaster into DI container and ModuleRegistry."""
    broadcaster = get_event_broadcaster()

    # Register broadcaster instance
    container.register_instance(SOCEventBroadcaster, broadcaster)

    # Instantiate Module Lifecycle
    module = RealtimeModule(broadcaster=broadcaster, di_container=container)
    container.register_instance(RealtimeModule, module)

    if registry is not None:
        registry.register(module)

    logger.info("RealtimeModule and SOCEventBroadcaster registered in DI container.")
    return module
