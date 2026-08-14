"""Remediation module implementing IModule, IHealthCheckable, and DI container registration."""

from __future__ import annotations

import time
from typing import Any, cast

from src.common.models import ComponentHealthDTO
from src.config.logging import get_logger
from src.container.di import Container
from src.interfaces.base import IHealthCheckable, IModule
from src.registry.module_registry import ModuleRegistry
from src.remediation.engine import RemediationEngine

logger = get_logger("scamon.remediation.module")


class RemediationModule(IModule, IHealthCheckable):
    """Enterprise Incident Response & SOC Automated Remediation Module for ScamON Enterprise."""

    def __init__(self) -> None:
        self.engine: RemediationEngine | None = None
        self._running: bool = False

    @property
    def name(self) -> str:
        return "remediation"

    @property
    def version(self) -> str:
        return "1.0.0"

    async def initialize(self) -> None:
        """Lifecycle hook: Initialize RemediationEngine."""
        self.engine = RemediationEngine()
        self._running = True
        logger.info("RemediationModule initialized successfully.")

    async def shutdown(self) -> None:
        """Lifecycle hook: Shutdown Remediation engine."""
        self._running = False
        logger.info("RemediationModule shut down successfully.")

    async def health_check(self) -> ComponentHealthDTO:
        """Lifecycle hook: Report remediation module health status."""
        start = time.perf_counter()
        status = "HEALTHY" if self._running else "UNHEALTHY"
        elapsed_ms = (time.perf_counter() - start) * 1000.0

        return ComponentHealthDTO(
            component_name=self.name,
            status=status,
            latency_ms=elapsed_ms,
            details={
                "engine": "RemediationEngine",
                "running": self._running,
            },
        )


def register_remediation_module(
    di_container: Container,
    module_registry: ModuleRegistry,
) -> RemediationModule:
    """Register RemediationModule and engine into Container and ModuleRegistry."""
    module = RemediationModule()

    di_container.register_instance(RemediationModule, module)
    di_container.register_instance(cast(type[Any], IHealthCheckable), module)

    module_registry.register(module)
    return module
