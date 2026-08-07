"""Authentication module implementing IModule, IHealthCheckable, and DI container registration."""

from __future__ import annotations

import time
from typing import Any, cast

from src.authentication.engine import AuthenticationVerificationEngine
from src.common.models import ComponentHealthDTO
from src.config.logging import get_logger
from src.container.di import Container
from src.interfaces.base import IHealthCheckable, IModule
from src.interfaces.event_publisher import IEventPublisher
from src.registry.module_registry import ModuleRegistry

logger = get_logger("scamon.authentication.module")


class AuthenticationModule(IModule, IHealthCheckable):
    """Authentication Verification Module (SPF, DKIM, DMARC, ARC) for ScamON Enterprise."""

    def __init__(self, event_publisher: IEventPublisher | None = None) -> None:
        self.event_publisher = event_publisher
        self.engine: AuthenticationVerificationEngine | None = None
        self._running: bool = False

    @property
    def name(self) -> str:
        return "authentication"

    @property
    def version(self) -> str:
        return "1.0.0"

    async def initialize(self) -> None:
        """Lifecycle hook: Initialize AuthenticationVerificationEngine."""
        self.engine = AuthenticationVerificationEngine(
            event_publisher=self.event_publisher
        )
        self._running = True
        logger.info("AuthenticationModule initialized successfully.")

    async def shutdown(self) -> None:
        """Lifecycle hook: Shutdown authentication verification engine."""
        self._running = False
        logger.info("AuthenticationModule shut down successfully.")

    async def health_check(self) -> ComponentHealthDTO:
        """Lifecycle hook: Report authentication module health status."""
        start = time.perf_counter()
        status = "HEALTHY" if self._running else "UNHEALTHY"
        elapsed_ms = (time.perf_counter() - start) * 1000.0

        return ComponentHealthDTO(
            component_name=self.name,
            status=status,
            latency_ms=elapsed_ms,
            details={
                "engine": "AuthenticationVerificationEngine",
                "protocols": [
                    "SPF (RFC 7208)",
                    "DKIM (RFC 6376)",
                    "DMARC (RFC 7489)",
                    "ARC (RFC 8617)",
                ],
                "running": self._running,
            },
        )


def register_authentication_module(
    di_container: Container,
    module_registry: ModuleRegistry,
    event_publisher: IEventPublisher | None = None,
) -> AuthenticationModule:
    """Register AuthenticationModule and engine into Container and ModuleRegistry."""
    auth_module = AuthenticationModule(event_publisher=event_publisher)

    di_container.register_instance(AuthenticationModule, auth_module)
    di_container.register_instance(cast(type[Any], IHealthCheckable), auth_module)

    module_registry.register(auth_module)
    return auth_module
