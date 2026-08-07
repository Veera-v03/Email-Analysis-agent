"""Database health checker module implementing IHealthCheckable."""

from __future__ import annotations

import time
from typing import Any

from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncEngine

from src.common.models import ComponentHealthDTO
from src.config.logging import get_logger
from src.interfaces.base import IHealthCheckable

logger = get_logger("scamon.database.health")


class DatabaseHealthChecker(IHealthCheckable):
    """Health check component validating database connection and pool metrics."""

    def __init__(self, engine: AsyncEngine) -> None:
        self.engine = engine

    async def health_check(self) -> ComponentHealthDTO:
        """Ping database with SELECT 1 query and measure execution latency."""
        start_time = time.perf_counter()
        try:
            async with self.engine.connect() as conn:
                res = await conn.execute(text("SELECT 1"))
                row = res.scalar()
                assert row == 1

            elapsed_ms = (time.perf_counter() - start_time) * 1000

            # Safely extract connection pool statistics
            pool_obj = self.engine.pool
            pool_size_fn = getattr(pool_obj, "size", None)
            checkedin_fn = getattr(pool_obj, "checkedin", None)
            checkedout_fn = getattr(pool_obj, "checkedout", None)
            overflow_fn = getattr(pool_obj, "overflow", None)

            pool_status: dict[str, Any] = {
                "pool_size": pool_size_fn() if callable(pool_size_fn) else 0,
                "checked_in": checkedin_fn() if callable(checkedin_fn) else 0,
                "checked_out": checkedout_fn() if callable(checkedout_fn) else 0,
                "overflow": overflow_fn() if callable(overflow_fn) else 0,
            }

            return ComponentHealthDTO(
                component_name="postgresql_database",
                status="HEALTHY",
                latency_ms=elapsed_ms,
                details={"ping": "SELECT 1 PASS", "pool": pool_status},
            )
        except Exception as exc:
            elapsed_ms = (time.perf_counter() - start_time) * 1000
            logger.error("Database health check failed: %s", exc)
            return ComponentHealthDTO(
                component_name="postgresql_database",
                status="UNHEALTHY",
                latency_ms=elapsed_ms,
                details={"error": str(exc)},
            )
