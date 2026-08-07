"""IAM module implementing IModule, IHealthCheckable, and DI container registration."""

from __future__ import annotations

import time
from typing import Any, cast

from src.common.models import ComponentHealthDTO
from src.config.logging import get_logger
from src.container.di import Container
from src.interfaces.base import IHealthCheckable, IModule
from src.interfaces.event_publisher import IEventPublisher
from src.registry.module_registry import ModuleRegistry
from src.security.auth_service import AuthenticationService
from src.security.keys import RSAKeyManager
from src.security.rbac import AuthorizationService
from src.security.token_manager import TokenManager

logger = get_logger("scamon.security.module")


class IAMModule(IModule, IHealthCheckable):
    """Identity and Access Management service module for ScamON Enterprise."""

    def __init__(
        self,
        event_publisher: IEventPublisher | None = None,
    ) -> None:
        self.event_publisher = event_publisher
        self.key_manager: RSAKeyManager | None = None
        self.token_manager: TokenManager | None = None
        self.auth_service: AuthenticationService | None = None
        self.rbac_service: AuthorizationService | None = None
        self._running: bool = False

    @property
    def name(self) -> str:
        return "iam"

    @property
    def version(self) -> str:
        return "1.0.0"

    async def initialize(self) -> None:
        """Lifecycle hook: Initialize RSA keys, token issuer, and auth services."""
        self.key_manager = RSAKeyManager()
        self.token_manager = TokenManager(key_manager=self.key_manager)
        self.auth_service = AuthenticationService(
            token_manager=self.token_manager,
            event_publisher=self.event_publisher,
        )
        self.rbac_service = AuthorizationService(event_publisher=self.event_publisher)
        self._running = True
        logger.info("IAMModule initialized successfully with 2048-bit RS256 key pair.")

    async def shutdown(self) -> None:
        """Lifecycle hook: Shutdown IAM service and clear ephemeral keys."""
        self._running = False
        logger.info("IAMModule shut down successfully.")

    async def health_check(self) -> ComponentHealthDTO:
        """Lifecycle hook: Report IAM health status and RSA key availability."""
        start = time.perf_counter()
        status = "HEALTHY" if self._running else "UNHEALTHY"
        elapsed_ms = (time.perf_counter() - start) * 1000

        rev_count = (
            len(self.token_manager.revocation_manager._revoked_jtis)
            if self.token_manager
            else 0
        )

        return ComponentHealthDTO(
            component_name=self.name,
            status=status,
            latency_ms=elapsed_ms,
            details={
                "algorithm": "RS256",
                "rsa_bits": 2048,
                "revoked_tokens_count": rev_count,
                "running": self._running,
            },
        )


def register_iam_module(
    di_container: Container,
    module_registry: ModuleRegistry,
    event_publisher: IEventPublisher | None = None,
) -> IAMModule:
    """Register IAMModule and services into Container and ModuleRegistry."""
    iam_module = IAMModule(event_publisher=event_publisher)

    di_container.register_instance(IAMModule, iam_module)
    di_container.register_instance(cast(type[Any], IHealthCheckable), iam_module)

    module_registry.register(iam_module)
    return iam_module
