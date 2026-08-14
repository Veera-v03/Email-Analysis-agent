"""Threat Correlation module implementing IModule, IHealthCheckable, and DI container registration."""

from __future__ import annotations

import time
from typing import Any, cast

from src.common.models import ComponentHealthDTO
from src.config.logging import get_logger
from src.container.di import Container
from src.interfaces.base import IHealthCheckable, IModule
from src.registry.module_registry import ModuleRegistry
from src.threat_correlation.engine import ThreatCorrelationEngine

logger = get_logger("scamon.threat_correlation.module")


class ThreatCorrelationModule(IModule, IHealthCheckable):
    """Threat Correlation & Campaign Intelligence Module for ScamON Enterprise."""

    def __init__(self) -> None:
        self.engine: ThreatCorrelationEngine | None = None
        self._running: bool = False

    @property
    def name(self) -> str:
        return "threat_correlation"

    @property
    def version(self) -> str:
        return "1.0.0"

    async def initialize(self) -> None:
        """Lifecycle hook: Initialize ThreatCorrelationEngine."""
        self.engine = ThreatCorrelationEngine()
        self._running = True
        logger.info("ThreatCorrelationModule initialized successfully.")

    async def shutdown(self) -> None:
        """Lifecycle hook: Shutdown Threat Correlation engine."""
        self._running = False
        logger.info("ThreatCorrelationModule shut down successfully.")

    async def health_check(self) -> ComponentHealthDTO:
        """Lifecycle hook: Report threat correlation module health status."""
        start = time.perf_counter()
        status = "HEALTHY" if self._running else "UNHEALTHY"
        elapsed_ms = (time.perf_counter() - start) * 1000.0

        return ComponentHealthDTO(
            component_name=self.name,
            status=status,
            latency_ms=elapsed_ms,
            details={
                "engine": "ThreatCorrelationEngine",
                "running": self._running,
            },
        )


def register_threat_correlation_module(
    di_container: Container,
    module_registry: ModuleRegistry,
) -> ThreatCorrelationModule:
    """Register ThreatCorrelationModule and engine into Container and ModuleRegistry."""
    module = ThreatCorrelationModule()

    di_container.register_instance(ThreatCorrelationModule, module)
    di_container.register_instance(cast(type[Any], IHealthCheckable), module)

    module_registry.register(module)
    return module
