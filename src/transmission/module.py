"""Transmission module implementing IModule, IHealthCheckable, and DI container registration."""

from __future__ import annotations

import time
from typing import Any, cast

from src.common.models import ComponentHealthDTO
from src.config.logging import get_logger
from src.container.di import Container
from src.interfaces.base import IHealthCheckable, IModule
from src.interfaces.event_publisher import IEventPublisher
from src.registry.module_registry import ModuleRegistry
from src.transmission.engine import TransmissionAnalysisEngine

logger = get_logger("scamon.transmission.module")


class TransmissionModule(IModule, IHealthCheckable):
    """Header & Transmission Analysis Module for ScamON Enterprise."""

    def __init__(self, event_publisher: IEventPublisher | None = None) -> None:
        self.event_publisher = event_publisher
        self.engine: TransmissionAnalysisEngine | None = None
        self._running: bool = False

    @property
    def name(self) -> str:
        return "transmission"

    @property
    def version(self) -> str:
        return "1.0.0"

    async def initialize(self) -> None:
        """Lifecycle hook: Initialize TransmissionAnalysisEngine."""
        self.engine = TransmissionAnalysisEngine(event_publisher=self.event_publisher)
        self._running = True
        logger.info("TransmissionModule initialized successfully.")

    async def shutdown(self) -> None:
        """Lifecycle hook: Shutdown transmission engine."""
        self._running = False
        logger.info("TransmissionModule shut down successfully.")

    async def health_check(self) -> ComponentHealthDTO:
        """Lifecycle hook: Report transmission module health status."""
        start = time.perf_counter()
        status = "HEALTHY" if self._running else "UNHEALTHY"
        elapsed_ms = (time.perf_counter() - start) * 1000.0

        return ComponentHealthDTO(
            component_name=self.name,
            status=status,
            latency_ms=elapsed_ms,
            details={
                "engine": "TransmissionAnalysisEngine",
                "rfc_compliance": "RFC 5322 / RFC 5321",
                "running": self._running,
            },
        )


def register_transmission_module(
    di_container: Container,
    module_registry: ModuleRegistry,
    event_publisher: IEventPublisher | None = None,
) -> TransmissionModule:
    """Register TransmissionModule and engine into Container and ModuleRegistry."""
    transmission_module = TransmissionModule(event_publisher=event_publisher)

    di_container.register_instance(TransmissionModule, transmission_module)
    di_container.register_instance(
        cast(type[Any], IHealthCheckable), transmission_module
    )

    module_registry.register(transmission_module)
    return transmission_module
