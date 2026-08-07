"""Async Session Factory, context managers, and RLS tenant setters."""

from __future__ import annotations

from collections.abc import AsyncGenerator
from contextlib import asynccontextmanager
from uuid import UUID

from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncEngine, AsyncSession, async_sessionmaker

from src.database.engine import build_async_engine


def build_async_session_factory(
    engine: AsyncEngine | None = None,
) -> async_sessionmaker[AsyncSession]:
    """Construct an async sessionmaker bound to the AsyncEngine."""
    target_engine = engine or build_async_engine()
    return async_sessionmaker(
        bind=target_engine,
        class_=AsyncSession,
        expire_on_commit=False,
        autoflush=False,
    )


@asynccontextmanager
async def get_session_context(
    session_factory: async_sessionmaker[AsyncSession] | None = None,
) -> AsyncGenerator[AsyncSession]:
    """Async context manager yielding an isolated AsyncSession for background tasks."""
    factory = session_factory or build_async_session_factory()
    async with factory() as session:
        try:
            yield session
            await session.commit()
        except Exception:
            await session.rollback()
            raise


async def get_async_session() -> AsyncGenerator[AsyncSession]:
    """FastAPI dependency yielding an async database session per HTTP request."""
    factory = build_async_session_factory()
    async with factory() as session:
        try:
            yield session
            await session.commit()
        except Exception:
            await session.rollback()
            raise


async def set_session_tenant_id(session: AsyncSession, tenant_id: UUID) -> None:
    """Set app.current_tenant_id session variable for PostgreSQL Row-Level Security (RLS)."""
    await session.execute(
        text("SELECT set_config('app.current_tenant_id', :tenant_id, true)"),
        {"tenant_id": str(tenant_id)},
    )
