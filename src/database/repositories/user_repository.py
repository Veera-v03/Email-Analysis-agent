"""User Repository implementation for tenant-isolated user operations."""

from __future__ import annotations

from uuid import UUID

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from src.database.models import User
from src.database.repositories.base import BaseRepository
from src.interfaces.repositories import IUserRepository


class UserRepository(BaseRepository[User, UUID], IUserRepository):
    """Repository handling User ORM operations with tenant isolation."""

    def __init__(self, session: AsyncSession) -> None:
        super().__init__(User, session)

    async def get_by_email(self, tenant_id: UUID, email: str) -> User | None:
        """Fetch user by email within a specific tenant."""
        stmt = select(User).where(
            User.tenant_id == tenant_id,
            User.email == email.lower(),
        )
        result = await self.session.execute(stmt)
        return result.scalar_one_or_none()

    async def list_by_tenant(
        self, tenant_id: UUID, limit: int = 100, offset: int = 0
    ) -> list[User]:
        """List users belonging to a tenant."""
        stmt = (
            select(User).where(User.tenant_id == tenant_id).limit(limit).offset(offset)
        )
        result = await self.session.execute(stmt)
        return list(result.scalars().all())
