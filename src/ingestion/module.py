"""Ingestion module implementing IModule, IHealthCheckable, and DI container registration."""

from __future__ import annotations

import time
from typing import Any, cast

from src.common.models import ComponentHealthDTO
from src.config.logging import get_logger
from src.container.di import Container
from src.ingestion.pipeline import IngestionPipeline
from src.interfaces.base import IHealthCheckable, IModule
from src.interfaces.event_publisher import IEventPublisher
from src.registry.module_registry import ModuleRegistry

logger = get_logger("scamon.ingestion.module")


class IngestionModule(IModule, IHealthCheckable):
    """Email Ingestion Platform module for ScamON Enterprise."""

    def __init__(self, event_publisher: IEventPublisher | None = None) -> None:
        self.event_publisher = event_publisher
        self.pipeline: IngestionPipeline | None = None
        self._running: bool = False

    @property
    def name(self) -> str:
        return "ingestion"

    @property
    def version(self) -> str:
        return "1.0.0"

    async def initialize(self) -> None:
        """Lifecycle hook: Initialize IngestionPipeline and providers."""
        self.pipeline = IngestionPipeline(event_publisher=self.event_publisher)
        self._running = True
        logger.info("IngestionModule initialized successfully.")

    async def shutdown(self) -> None:
        """Lifecycle hook: Shutdown ingestion pipeline."""
        self._running = False
        logger.info("IngestionModule shut down successfully.")

    async def health_check(self) -> ComponentHealthDTO:
        """Lifecycle hook: Report ingestion platform health and supported providers."""
        start = time.perf_counter()
        status = "HEALTHY" if self._running else "UNHEALTHY"
        elapsed_ms = (time.perf_counter() - start) * 1000

        return ComponentHealthDTO(
            component_name=self.name,
            status=status,
            latency_ms=elapsed_ms,
            details={
                "supported_providers": ["GMAIL", "MS_GRAPH"],
                "active_provider": "GMAIL",
                "running": self._running,
            },
        )


def register_ingestion_module(
    di_container: Container,
    module_registry: ModuleRegistry,
    event_publisher: IEventPublisher | None = None,
) -> IngestionModule:
    """Register IngestionModule and pipeline into Container and ModuleRegistry."""
    ingestion_module = IngestionModule(event_publisher=event_publisher)

    di_container.register_instance(IngestionModule, ingestion_module)
    di_container.register_instance(cast(type[Any], IHealthCheckable), ingestion_module)

    module_registry.register(ingestion_module)
    return ingestion_module
