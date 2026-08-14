"""URL Intelligence module implementing IModule, IHealthCheckable, and DI container registration."""

from __future__ import annotations

import time
from typing import Any, cast

from src.common.models import ComponentHealthDTO
from src.config.logging import get_logger
from src.container.di import Container
from src.interfaces.base import IHealthCheckable, IModule
from src.registry.module_registry import ModuleRegistry
from src.url_intelligence.engine import URLIntelligenceEngine

logger = get_logger("scamon.url_intelligence.module")


class URLIntelligenceModule(IModule, IHealthCheckable):
    """URL & Sandbox Intelligence Module for ScamON Enterprise."""

    def __init__(self) -> None:
        self.engine: URLIntelligenceEngine | None = None
        self._running: bool = False

    @property
    def name(self) -> str:
        return "url_intelligence"

    @property
    def version(self) -> str:
        return "1.0.0"

    async def initialize(self) -> None:
        """Lifecycle hook: Initialize URLIntelligenceEngine."""
        self.engine = URLIntelligenceEngine()
        self._running = True
        logger.info("URLIntelligenceModule initialized successfully.")

    async def shutdown(self) -> None:
        """Lifecycle hook: Shutdown URL intelligence engine."""
        self._running = False
        logger.info("URLIntelligenceModule shut down successfully.")

    async def health_check(self) -> ComponentHealthDTO:
        """Lifecycle hook: Report URL intelligence module health status."""
        start = time.perf_counter()
        status = "HEALTHY" if self._running else "UNHEALTHY"
        elapsed_ms = (time.perf_counter() - start) * 1000.0

        return ComponentHealthDTO(
            component_name=self.name,
            status=status,
            latency_ms=elapsed_ms,
            details={
                "engine": "URLIntelligenceEngine",
                "running": self._running,
            },
        )


def register_url_module(
    di_container: Container,
    module_registry: ModuleRegistry,
) -> URLIntelligenceModule:
    """Register URLIntelligenceModule and engine into Container and ModuleRegistry."""
    url_module = URLIntelligenceModule()

    di_container.register_instance(URLIntelligenceModule, url_module)
    di_container.register_instance(cast(type[Any], IHealthCheckable), url_module)

    module_registry.register(url_module)
    return url_module
