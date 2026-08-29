"""Module 21 lifecycle registration and health check manager implementation."""

from __future__ import annotations

from typing import Any

from src.common.models import ComponentHealthDTO
from src.config.enterprise_config import settings
from src.config.logging import get_logger
from src.container.di import Container
from src.ingestion_gateway.manager import IngestionGatewayManager
from src.interfaces.base import IHealthCheckable, IModule
from src.interfaces.event_publisher import IEventPublisher
from src.registry.module_registry import ModuleRegistry

logger = get_logger("scamon.ingestion_gateway.module")


class IngestionGatewayModule(IModule, IHealthCheckable):
    """Module 21 Enterprise Live Mailbox Ingestion Gateway Lifecycle Manager."""

    def __init__(
        self,
        manager: IngestionGatewayManager | None = None,
        di_container: Container | None = None,
    ) -> None:
        self.container = di_container or Container()
        self.manager = manager or IngestionGatewayManager(di_container=self.container)
        self._is_initialized = False

    @property
    def name(self) -> str:
        return "ingestion_gateway"

    @property
    def version(self) -> str:
        return "1.0.0"

    async def initialize(self) -> None:
        """Initialize IngestionGatewayModule resources, DI bindings, and active daemons."""
        if self._is_initialized:
            return

        logger.info("Initializing IngestionGatewayModule v1.0.0...")

        # 1. Wire EventPublisher if available
        try:
            if self.container.has(IEventPublisher) and not self.manager.event_publisher:
                self.manager.event_publisher = self.container.resolve(IEventPublisher)
                logger.info("IngestionGatewayModule wired EventPublisher.")
        except Exception as exc:
            logger.warning("EventPublisher resolution during gateway init: %s", exc)

        # 2. Auto-start daemons if enabled in configuration
        if settings.ingestion_enabled:
            await self.manager.start_all()

        self._is_initialized = True
        logger.info("IngestionGatewayModule initialized successfully.")

    async def shutdown(self) -> None:
        """Gracefully shutdown all active ingestion daemons."""
        logger.info("Shutting down IngestionGatewayModule...")
        await self.manager.stop_all()
        self._is_initialized = False
        logger.info("IngestionGatewayModule shutdown complete.")

    async def health_check(self) -> ComponentHealthDTO:
        """Return operational health status and daemon metrics."""
        status_info = await self.manager.get_health_status()
        overall_status = "HEALTHY" if self._is_initialized and status_info.get("overall_status") == "HEALTHY" else "DEGRADED"

        return ComponentHealthDTO(
            component_name=self.name,
            status=overall_status,
            details={
                "initialized": self._is_initialized,
                "version": self.version,
                **status_info,
            },
        )


def register_ingestion_gateway_module(
    container: Container, registry: ModuleRegistry
) -> IngestionGatewayModule:
    """Register IngestionGatewayModule with global DI Container and ModuleRegistry."""
    manager = IngestionGatewayManager(di_container=container)
    mod = IngestionGatewayModule(manager=manager, di_container=container)

    container.register_instance(IngestionGatewayManager, manager)
    container.register_instance(IngestionGatewayModule, mod)
    registry.register(mod)

    return mod
