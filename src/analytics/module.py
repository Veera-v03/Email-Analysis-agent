"""Module 19 lifecycle registration and health check module implementation."""

from __future__ import annotations

from typing import Any

from src.common.models import ComponentHealthDTO
from src.config.logging import get_logger
from src.container.di import Container
from src.interfaces.base import IHealthCheckable, IModule
from src.registry.module_registry import ModuleRegistry

logger = get_logger("scamon.analytics.module")


class AnalyticsModule(IModule, IHealthCheckable):
    """Module 19 Enterprise Threat Analytics and Reporting Lifecycle Manager."""

    def __init__(self, di_container: Container | None = None) -> None:
        self.container = di_container or Container()
        self._is_initialized = False

    @property
    def name(self) -> str:
        return "analytics"

    @property
    def version(self) -> str:
        return "1.0.0"

    async def initialize(self) -> None:
        """Initialize AnalyticsModule resources and DI bindings."""
        if self._is_initialized:
            return
        logger.info("Initializing AnalyticsModule v1.0.0...")
        self._is_initialized = True
        logger.info("AnalyticsModule initialized successfully.")

    async def shutdown(self) -> None:
        """Shutdown AnalyticsModule resources cleanly."""
        logger.info("Shutting down AnalyticsModule...")
        self._is_initialized = False
        logger.info("AnalyticsModule shutdown complete.")

    async def health_check(self) -> ComponentHealthDTO:
        """Return component health status."""
        return ComponentHealthDTO(
            component_name="analytics",
            status="HEALTHY" if self._is_initialized else "DEGRADED",
            details={
                "initialized": self._is_initialized,
                "version": self.version,
            },
        )


def register_analytics_module(
    container: Container, registry: ModuleRegistry
) -> AnalyticsModule:
    """Helper function registering AnalyticsModule with global container and registry."""
    mod = AnalyticsModule(di_container=container)
    container.register_instance(AnalyticsModule, mod)
    registry.register(mod)
    return mod
