"""Parsing module implementing IModule, IHealthCheckable, and DI container registration."""

from __future__ import annotations

import time
from typing import Any, cast

from src.common.models import ComponentHealthDTO
from src.config.logging import get_logger
from src.container.di import Container
from src.interfaces.base import IHealthCheckable, IModule
from src.interfaces.event_publisher import IEventPublisher
from src.parsing.engine import MimeParserEngine
from src.registry.module_registry import ModuleRegistry

logger = get_logger("scamon.parsing.module")


class ParsingModule(IModule, IHealthCheckable):
    """MIME Parsing & Decomposition Module for ScamON Enterprise."""

    def __init__(self, event_publisher: IEventPublisher | None = None) -> None:
        self.event_publisher = event_publisher
        self.engine: MimeParserEngine | None = None
        self._running: bool = False

    @property
    def name(self) -> str:
        return "parsing"

    @property
    def version(self) -> str:
        return "1.0.0"

    async def initialize(self) -> None:
        """Lifecycle hook: Initialize MimeParserEngine."""
        self.engine = MimeParserEngine(event_publisher=self.event_publisher)
        self._running = True
        logger.info("ParsingModule initialized successfully.")

    async def shutdown(self) -> None:
        """Lifecycle hook: Shutdown parsing engine."""
        self._running = False
        logger.info("ParsingModule shut down successfully.")

    async def health_check(self) -> ComponentHealthDTO:
        """Lifecycle hook: Report parsing module health status."""
        start = time.perf_counter()
        status = "HEALTHY" if self._running else "UNHEALTHY"
        elapsed_ms = (time.perf_counter() - start) * 1000.0

        return ComponentHealthDTO(
            component_name=self.name,
            status=status,
            latency_ms=elapsed_ms,
            details={
                "parser_engine": "MimeParserEngine",
                "rfc_compliance": "RFC 5322 / RFC 2045",
                "running": self._running,
            },
        )


def register_parsing_module(
    di_container: Container,
    module_registry: ModuleRegistry,
    event_publisher: IEventPublisher | None = None,
) -> ParsingModule:
    """Register ParsingModule and engine into Container and ModuleRegistry."""
    parsing_module = ParsingModule(event_publisher=event_publisher)

    di_container.register_instance(ParsingModule, parsing_module)
    di_container.register_instance(cast(type[Any], IHealthCheckable), parsing_module)

    module_registry.register(parsing_module)
    return parsing_module
