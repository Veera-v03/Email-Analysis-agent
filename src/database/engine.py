"""Async database engine creation and management for ScamON Enterprise."""

from __future__ import annotations

import os
from typing import Any

from sqlalchemy.ext.asyncio import AsyncEngine, create_async_engine

from src.config.logging import get_logger
from src.config.settings import get_settings

logger = get_logger("scamon.database.engine")


def get_database_url() -> str:
    """Resolve production PostgreSQL connection URL from settings or environment."""
    settings = get_settings()

    url: str | None = None
    if settings.postgres_url:
        url = settings.postgres_url.get_secret_value()
    elif os.getenv("DATABASE_URL"):
        url = os.getenv("DATABASE_URL")

    if not url:
        # Default local development fallback
        url = "postgresql+psycopg://postgres:veera0306@localhost:5432/scamon"

    # Normalize driver prefixes to asyncpg for async engine compatibility
    if "postgresql+psycopg://" in url:
        url = url.replace("postgresql+psycopg://", "postgresql+asyncpg://")
    elif url.startswith("postgresql://"):
        url = url.replace("postgresql://", "postgresql+asyncpg://", 1)
    elif url.startswith("postgres://"):
        url = url.replace("postgres://", "postgresql+asyncpg://", 1)

    return url


def build_async_engine(database_url: str | None = None) -> AsyncEngine:
    """Build and configure a production AsyncEngine instance.

    Args:
        database_url: Optional connection URL override.

    Returns:
        Configured SQLAlchemy AsyncEngine instance.
    """
    url = database_url or get_database_url()
    logger.info("Initializing AsyncEngine for database URL: %s", url.split("@")[-1])

    kwargs: dict[str, Any] = {
        "echo": False,
        "pool_pre_ping": True,
    }
    if "sqlite" not in url:
        kwargs["pool_size"] = 10
        kwargs["max_overflow"] = 20
        kwargs["pool_recycle"] = 3600

    engine = create_async_engine(url, **kwargs)
    return engine
