"""Database module implementing IModule and DI registration helper."""

from __future__ import annotations

from typing import Any, cast

from sqlalchemy.ext.asyncio import AsyncEngine, AsyncSession, async_sessionmaker

from src.common.models import ComponentHealthDTO
from src.config.logging import get_logger
from src.container.di import Container
from src.database.engine import build_async_engine
from src.database.health import DatabaseHealthChecker
from src.database.session import build_async_session_factory
from src.interfaces.base import IHealthCheckable, IModule
from src.interfaces.repositories import (
    IIncidentRepository,
    ITenantPolicyRepository,
    ITenantRepository,
    IUserRepository,
)
from src.registry.module_registry import ModuleRegistry

logger = get_logger("scamon.database.module")


class DatabaseModule(IModule):
    """Modular database persistence service for ScamON Enterprise."""

    def __init__(self, database_url: str | None = None) -> None:
        self.database_url = database_url
        self.engine: AsyncEngine | None = None
        self.session_factory: async_sessionmaker[AsyncSession] | None = None
        self.health_checker: DatabaseHealthChecker | None = None

    @property
    def name(self) -> str:
        return "database"

    @property
    def version(self) -> str:
        return "1.0.0"

    async def initialize(self) -> None:
        """Lifecycle hook: Initialize AsyncEngine and session factory."""
        self.engine = build_async_engine(self.database_url)
        self.session_factory = build_async_session_factory(self.engine)
        self.health_checker = DatabaseHealthChecker(self.engine)
        logger.info("DatabaseModule initialized successfully.")

    async def shutdown(self) -> None:
        """Lifecycle hook: Orderly shutdown of AsyncEngine connection pool."""
        if self.engine:
            await self.engine.dispose()
            logger.info("DatabaseModule connection pool disposed.")

    async def health_check(self) -> ComponentHealthDTO:
        """Lifecycle hook: Delegate health status check to DatabaseHealthChecker."""
        if self.health_checker:
            return await self.health_checker.health_check()
        return ComponentHealthDTO(
            component_name=self.name,
            status="UNHEALTHY",
            latency_ms=0.0,
            details={"error": "DatabaseModule not initialized"},
        )


def register_database_module(
    di_container: Container,
    module_registry: ModuleRegistry,
    database_url: str | None = None,
) -> DatabaseModule:
    """Register DatabaseModule and session factories into Container and ModuleRegistry."""
    db_module = DatabaseModule(database_url)

    di_container.register_instance(DatabaseModule, db_module)
    di_container.register_instance(cast(type[Any], IHealthCheckable), db_module)

    module_registry.register(db_module)
    return db_module
