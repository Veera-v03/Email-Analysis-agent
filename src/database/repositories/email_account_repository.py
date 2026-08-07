"""EmailAccount Repository implementation."""

from __future__ import annotations

from datetime import datetime
from uuid import UUID

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from src.database.models import EmailAccount
from src.database.repositories.base import BaseRepository


class EmailAccountRepository(BaseRepository[EmailAccount, UUID]):
    """Repository handling EmailAccount ORM operations."""

    def __init__(self, session: AsyncSession) -> None:
        super().__init__(EmailAccount, session)

    async def get_by_address(
        self, tenant_id: UUID, email_address: str
    ) -> EmailAccount | None:
        """Fetch EmailAccount by email address within a tenant."""
        stmt = select(EmailAccount).where(
            EmailAccount.tenant_id == tenant_id,
            EmailAccount.email_address == email_address.lower(),
        )
        result = await self.session.execute(stmt)
        return result.scalar_one_or_none()

    async def update_tokens(
        self,
        account_id: UUID,
        access_token: str,
        refresh_token: str | None = None,
        token_expiry: datetime | None = None,
    ) -> EmailAccount | None:
        """Update OAuth2 tokens for an email account."""
        account = await self.get_by_id(account_id)
        if account:
            account.access_token = access_token
            if refresh_token:
                account.refresh_token = refresh_token
            if token_expiry:
                account.token_expiry = token_expiry
            await self.session.flush()
            await self.session.refresh(account)
        return account
