"""Orchestrator module implementing IModule, IHealthCheckable, and DI container registration."""

from __future__ import annotations

import time
from typing import Any, cast

from src.common.models import ComponentHealthDTO
from src.config.logging import get_logger
from src.container.di import Container
from src.interfaces.base import IHealthCheckable, IModule
from src.interfaces.event_publisher import IEventPublisher
from src.orchestrator.engine import OrchestratorEngine
from src.registry.module_registry import ModuleRegistry

logger = get_logger("scamon.orchestrator.module")


class OrchestratorModule(IModule, IHealthCheckable):
    """Pipeline Orchestrator & Modular Monolith Integration Module for ScamON Enterprise."""

    def __init__(self, event_publisher: IEventPublisher | None = None) -> None:
        self.event_publisher = event_publisher
        self.engine: OrchestratorEngine | None = None
        self._running: bool = False

    @property
    def name(self) -> str:
        return "orchestrator"

    @property
    def version(self) -> str:
        return "1.0.0"

    async def initialize(self) -> None:
        """Lifecycle hook: Initialize OrchestratorEngine."""
        self.engine = OrchestratorEngine(event_publisher=self.event_publisher)
        self._running = True
        logger.info("OrchestratorModule initialized successfully.")

    async def shutdown(self) -> None:
        """Lifecycle hook: Shutdown orchestrator engine."""
        self._running = False
        logger.info("OrchestratorModule shut down successfully.")

    async def health_check(self) -> ComponentHealthDTO:
        """Lifecycle hook: Report orchestrator module health status."""
        start = time.perf_counter()
        status = "HEALTHY" if self._running else "UNHEALTHY"
        elapsed_ms = (time.perf_counter() - start) * 1000.0

        return ComponentHealthDTO(
            component_name=self.name,
            status=status,
            latency_ms=elapsed_ms,
            details={
                "engine": "OrchestratorEngine",
                "orchestrator": "EmailSecurityPipelineOrchestrator",
                "running": self._running,
            },
        )


def register_orchestrator_module(
    di_container: Container,
    module_registry: ModuleRegistry,
    event_publisher: IEventPublisher | None = None,
) -> OrchestratorModule:
    """Register OrchestratorModule and engine into Container and ModuleRegistry."""
    orch_module = OrchestratorModule(event_publisher=event_publisher)

    di_container.register_instance(OrchestratorModule, orch_module)
    di_container.register_instance(cast(type[Any], IHealthCheckable), orch_module)

    module_registry.register(orch_module)
    return orch_module
