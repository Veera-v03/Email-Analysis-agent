"""Ops module implementing IModule, IHealthCheckable, and DI container registration."""

from __future__ import annotations

import time
from typing import Any, cast

from src.common.models import ComponentHealthDTO
from src.config.logging import get_logger
from src.container.di import Container
from src.interfaces.base import IHealthCheckable, IModule
from src.ops.engine import OpsEngine
from src.registry.module_registry import ModuleRegistry

logger = get_logger("scamon.ops.module")


class OpsModule(IModule, IHealthCheckable):
    """Enterprise Operations, Storage & Production Deployment Suite Module for ScamON Enterprise."""

    def __init__(self) -> None:
        self.engine: OpsEngine | None = None
        self._running: bool = False

    @property
    def name(self) -> str:
        return "ops"

    @property
    def version(self) -> str:
        return "1.0.0"

    async def initialize(self) -> None:
        """Lifecycle hook: Initialize OpsEngine."""
        self.engine = OpsEngine()
        self._running = True
        logger.info("OpsModule initialized successfully.")

    async def shutdown(self) -> None:
        """Lifecycle hook: Shutdown Ops engine."""
        self._running = False
        logger.info("OpsModule shut down successfully.")

    async def health_check(self) -> ComponentHealthDTO:
        """Lifecycle hook: Report operations suite health status."""
        start = time.perf_counter()
        status = "HEALTHY" if self._running else "UNHEALTHY"
        elapsed_ms = (time.perf_counter() - start) * 1000.0

        details: dict[str, Any] = {"engine": "OpsEngine", "running": self._running}
        if self.engine:
            details.update(self.engine.get_status_summary())

        return ComponentHealthDTO(
            component_name=self.name,
            status=status,
            latency_ms=elapsed_ms,
            details=details,
        )


def register_ops_module(
    di_container: Container,
    module_registry: ModuleRegistry,
) -> OpsModule:
    """Register OpsModule and engine into Container and ModuleRegistry."""
    module = OpsModule()

    di_container.register_instance(OpsModule, module)
    di_container.register_instance(cast(type[Any], IHealthCheckable), module)

    module_registry.register(module)
    return module
