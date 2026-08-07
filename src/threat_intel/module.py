"""Threat Intel module implementing IModule, IHealthCheckable, and DI container registration."""

from __future__ import annotations

import time
from typing import Any, cast

from src.common.models import ComponentHealthDTO
from src.config.logging import get_logger
from src.container.di import Container
from src.interfaces.base import IHealthCheckable, IModule
from src.interfaces.event_publisher import IEventPublisher
from src.registry.module_registry import ModuleRegistry
from src.threat_intel.engine import ThreatIntelEngine

logger = get_logger("scamon.threat_intel.module")


class ThreatIntelModule(IModule, IHealthCheckable):
    """Threat Intelligence & IOC Enrichment Module for ScamON Enterprise."""

    def __init__(self, event_publisher: IEventPublisher | None = None) -> None:
        self.event_publisher = event_publisher
        self.engine: ThreatIntelEngine | None = None
        self._running: bool = False

    @property
    def name(self) -> str:
        return "threat_intel"

    @property
    def version(self) -> str:
        return "1.0.0"

    async def initialize(self) -> None:
        """Lifecycle hook: Initialize ThreatIntelEngine."""
        self.engine = ThreatIntelEngine(event_publisher=self.event_publisher)
        self._running = True
        logger.info("ThreatIntelModule initialized successfully.")

    async def shutdown(self) -> None:
        """Lifecycle hook: Shutdown threat intelligence engine."""
        self._running = False
        logger.info("ThreatIntelModule shut down successfully.")

    async def health_check(self) -> ComponentHealthDTO:
        """Lifecycle hook: Report threat intel module health status."""
        start = time.perf_counter()
        status = "HEALTHY" if self._running else "UNHEALTHY"
        elapsed_ms = (time.perf_counter() - start) * 1000.0

        return ComponentHealthDTO(
            component_name=self.name,
            status=status,
            latency_ms=elapsed_ms,
            details={
                "engine": "ThreatIntelEngine",
                "providers": [
                    "VirusTotal",
                    "AbuseIPDB",
                    "AlienVaultOTX",
                    "LocalThreatIntel",
                ],
                "running": self._running,
            },
        )


def register_threat_intel_module(
    di_container: Container,
    module_registry: ModuleRegistry,
    event_publisher: IEventPublisher | None = None,
) -> ThreatIntelModule:
    """Register ThreatIntelModule and engine into Container and ModuleRegistry."""
    threat_module = ThreatIntelModule(event_publisher=event_publisher)

    di_container.register_instance(ThreatIntelModule, threat_module)
    di_container.register_instance(cast(type[Any], IHealthCheckable), threat_module)

    module_registry.register(threat_module)
    return threat_module
