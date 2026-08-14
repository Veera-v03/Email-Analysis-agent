"""AI Decision Planner module implementing IModule, IHealthCheckable, and DI container registration."""

from __future__ import annotations

import time
from typing import Any, cast

from src.ai_decision.engine import AIDecisionEngine
from src.common.models import ComponentHealthDTO
from src.config.logging import get_logger
from src.container.di import Container
from src.interfaces.base import IHealthCheckable, IModule
from src.interfaces.event_publisher import IEventPublisher
from src.registry.module_registry import ModuleRegistry

logger = get_logger("scamon.ai_decision.module")


class AIDecisionModule(IModule, IHealthCheckable):
    """Enterprise AI Decision Planner & Explainability Engine Module for ScamON Enterprise."""

    def __init__(self, event_publisher: IEventPublisher | None = None) -> None:
        self.event_publisher = event_publisher
        self.engine: AIDecisionEngine | None = None
        self._running: bool = False

    @property
    def name(self) -> str:
        return "ai_decision"

    @property
    def version(self) -> str:
        return "1.0.0"

    async def initialize(self) -> None:
        """Lifecycle hook: Initialize AIDecisionEngine."""
        self.engine = AIDecisionEngine(event_publisher=self.event_publisher)
        self._running = True
        logger.info("AIDecisionModule initialized successfully.")

    async def shutdown(self) -> None:
        """Lifecycle hook: Shutdown AI decision engine."""
        self._running = False
        logger.info("AIDecisionModule shut down successfully.")

    async def health_check(self) -> ComponentHealthDTO:
        """Lifecycle hook: Report AI decision module health status."""
        start = time.perf_counter()
        status = "HEALTHY" if self._running else "UNHEALTHY"
        elapsed_ms = (time.perf_counter() - start) * 1000.0

        return ComponentHealthDTO(
            component_name=self.name,
            status=status,
            latency_ms=elapsed_ms,
            details={
                "engine": "AIDecisionEngine",
                "llm_provider": "GeminiLLMProvider",
                "running": self._running,
            },
        )


def register_ai_decision_module(
    di_container: Container,
    module_registry: ModuleRegistry,
    event_publisher: IEventPublisher | None = None,
) -> AIDecisionModule:
    """Register AIDecisionModule and engine into Container and ModuleRegistry."""
    ai_module = AIDecisionModule(event_publisher=event_publisher)

    di_container.register_instance(AIDecisionModule, ai_module)
    di_container.register_instance(cast(type[Any], IHealthCheckable), ai_module)

    module_registry.register(ai_module)
    return ai_module
