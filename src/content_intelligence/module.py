"""Content Intelligence module implementing IModule, IHealthCheckable, and DI container registration."""

from __future__ import annotations

import time
from typing import Any, cast

from src.common.models import ComponentHealthDTO
from src.config.logging import get_logger
from src.container.di import Container
from src.content_intelligence.engine import ContentIntelligenceEngine
from src.interfaces.base import IHealthCheckable, IModule
from src.registry.module_registry import ModuleRegistry

logger = get_logger("scamon.content_intelligence.module")


class ContentIntelligenceModule(IModule, IHealthCheckable):
    """Content & Media Intelligence Module for ScamON Enterprise."""

    def __init__(self) -> None:
        self.engine: ContentIntelligenceEngine | None = None
        self._running: bool = False

    @property
    def name(self) -> str:
        return "content_intelligence"

    @property
    def version(self) -> str:
        return "1.0.0"

    async def initialize(self) -> None:
        """Lifecycle hook: Initialize ContentIntelligenceEngine."""
        self.engine = ContentIntelligenceEngine()
        self._running = True
        logger.info("ContentIntelligenceModule initialized successfully.")

    async def shutdown(self) -> None:
        """Lifecycle hook: Shutdown content intelligence engine."""
        self._running = False
        logger.info("ContentIntelligenceModule shut down successfully.")

    async def health_check(self) -> ComponentHealthDTO:
        """Lifecycle hook: Report content intelligence module health status."""
        start = time.perf_counter()
        status = "HEALTHY" if self._running else "UNHEALTHY"
        elapsed_ms = (time.perf_counter() - start) * 1000.0

        return ComponentHealthDTO(
            component_name=self.name,
            status=status,
            latency_ms=elapsed_ms,
            details={
                "engine": "ContentIntelligenceEngine",
                "running": self._running,
            },
        )


def register_content_module(
    di_container: Container,
    module_registry: ModuleRegistry,
) -> ContentIntelligenceModule:
    """Register ContentIntelligenceModule and engine into Container and ModuleRegistry."""
    content_module = ContentIntelligenceModule()

    di_container.register_instance(ContentIntelligenceModule, content_module)
    di_container.register_instance(cast(type[Any], IHealthCheckable), content_module)

    module_registry.register(content_module)
    return content_module
