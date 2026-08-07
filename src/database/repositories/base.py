"""Generic Base Repository implementation using AsyncSession."""

from __future__ import annotations

from typing import Any, Generic, TypeVar
from uuid import UUID

from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from src.database.base import Base

T = TypeVar("T", bound=Base)
ID = TypeVar("ID", bound=UUID)


class BaseRepository(Generic[T, ID]):
    """Generic async repository providing CRUD operations for ORM entities."""

    def __init__(self, model_cls: type[T], session: AsyncSession) -> None:
        self.model_cls = model_cls
        self.session = session

    async def get_by_id(self, entity_id: ID) -> T | None:
        """Fetch entity by primary key ID."""
        return await self.session.get(self.model_cls, entity_id)

    async def list_all(self, limit: int = 100, offset: int = 0) -> list[T]:
        """List entities with limit and offset pagination."""
        stmt = select(self.model_cls).limit(limit).offset(offset)
        result = await self.session.execute(stmt)
        return list(result.scalars().all())

    async def create(self, entity: T) -> T:
        """Persist new entity instance."""
        self.session.add(entity)
        await self.session.flush()
        await self.session.refresh(entity)
        return entity

    async def update(self, entity: T) -> T:
        """Update existing entity instance."""
        await self.session.flush()
        await self.session.refresh(entity)
        return entity

    async def delete(self, entity_id: ID) -> bool:
        """Delete entity record by ID."""
        entity = await self.get_by_id(entity_id)
        if entity:
            await self.session.delete(entity)
            await self.session.flush()
            return True
        return False

    async def count(self) -> int:
        """Return total row count for entity table."""
        stmt = select(func.count()).select_from(self.model_cls)
        result = await self.session.execute(stmt)
        val = result.scalar()
        return val if val is not None else 0
