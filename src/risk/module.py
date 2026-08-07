"""Risk Assessment module implementing IModule, IHealthCheckable, and DI container registration."""

from __future__ import annotations

import time
from typing import Any, cast

from src.common.models import ComponentHealthDTO
from src.config.logging import get_logger
from src.container.di import Container
from src.interfaces.base import IHealthCheckable, IModule
from src.interfaces.event_publisher import IEventPublisher
from src.registry.module_registry import ModuleRegistry
from src.risk.engine import RiskAssessmentEngine

logger = get_logger("scamon.risk.module")


class RiskAssessmentModule(IModule, IHealthCheckable):
    """Enterprise Risk Assessment Module for ScamON Enterprise."""

    def __init__(self, event_publisher: IEventPublisher | None = None) -> None:
        self.event_publisher = event_publisher
        self.engine: RiskAssessmentEngine | None = None
        self._running: bool = False

    @property
    def name(self) -> str:
        return "risk_assessment"

    @property
    def version(self) -> str:
        return "1.0.0"

    async def initialize(self) -> None:
        """Lifecycle hook: Initialize RiskAssessmentEngine."""
        self.engine = RiskAssessmentEngine(event_publisher=self.event_publisher)
        self._running = True
        logger.info("RiskAssessmentModule initialized successfully.")

    async def shutdown(self) -> None:
        """Lifecycle hook: Shutdown risk assessment engine."""
        self._running = False
        logger.info("RiskAssessmentModule shut down successfully.")

    async def health_check(self) -> ComponentHealthDTO:
        """Lifecycle hook: Report risk assessment module health status."""
        start = time.perf_counter()
        status = "HEALTHY" if self._running else "UNHEALTHY"
        elapsed_ms = (time.perf_counter() - start) * 1000.0

        return ComponentHealthDTO(
            component_name=self.name,
            status=status,
            latency_ms=elapsed_ms,
            details={
                "engine": "RiskAssessmentEngine",
                "scoring_strategy": "DeterministicWeightedScoringStrategy",
                "running": self._running,
            },
        )


def register_risk_module(
    di_container: Container,
    module_registry: ModuleRegistry,
    event_publisher: IEventPublisher | None = None,
) -> RiskAssessmentModule:
    """Register RiskAssessmentModule and engine into Container and ModuleRegistry."""
    risk_module = RiskAssessmentModule(event_publisher=event_publisher)

    di_container.register_instance(RiskAssessmentModule, risk_module)
    di_container.register_instance(cast(type[Any], IHealthCheckable), risk_module)

    module_registry.register(risk_module)
    return risk_module
