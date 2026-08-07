"""RawEmail Repository implementation."""

from __future__ import annotations

from uuid import UUID

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from src.database.models import RawEmail
from src.database.repositories.base import BaseRepository


class RawEmailRepository(BaseRepository[RawEmail, UUID]):
    """Repository handling RawEmail ORM operations."""

    def __init__(self, session: AsyncSession) -> None:
        super().__init__(RawEmail, session)

    async def get_by_message_id(
        self, account_id: UUID, message_id: str
    ) -> RawEmail | None:
        """Fetch raw email by provider message ID."""
        stmt = select(RawEmail).where(
            RawEmail.account_id == account_id,
            RawEmail.message_id == message_id,
        )
        result = await self.session.execute(stmt)
        return result.scalar_one_or_none()
