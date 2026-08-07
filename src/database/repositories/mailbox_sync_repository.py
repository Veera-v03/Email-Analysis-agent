"""MailboxSyncState Repository implementation."""

from __future__ import annotations

from datetime import UTC, datetime
from uuid import UUID

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from src.database.models import EmailAccount, MailboxSyncState
from src.database.repositories.base import BaseRepository


class MailboxSyncStateRepository(BaseRepository[MailboxSyncState, UUID]):
    """Repository handling MailboxSyncState ORM operations."""

    def __init__(self, session: AsyncSession) -> None:
        super().__init__(MailboxSyncState, session)

    async def get_by_account_id(self, account_id: UUID) -> MailboxSyncState | None:
        """Fetch synchronization state for an EmailAccount."""
        stmt = select(MailboxSyncState).where(MailboxSyncState.account_id == account_id)
        result = await self.session.execute(stmt)
        return result.scalar_one_or_none()

    async def update_sync_progress(
        self,
        account_id: UUID,
        status: str,
        last_history_id: str | None = None,
        error_message: str | None = None,
    ) -> MailboxSyncState:
        """Update or create sync state for a mailbox account."""
        state = await self.get_by_account_id(account_id)
        now = datetime.now(UTC)

        if state:
            state.status = status
            state.last_sync_timestamp = now
            if last_history_id:
                state.last_history_id = last_history_id
            if error_message is not None:
                state.error_message = error_message
            await self.session.flush()
            await self.session.refresh(state)
            return state

        # Create new record if none exists
        account_obj = await self.session.get(EmailAccount, account_id)
        tenant_id = account_obj.tenant_id if account_obj else UUID(int=0)

        new_state = MailboxSyncState(
            account_id=account_id,
            tenant_id=tenant_id,
            status=status,
            last_history_id=last_history_id,
            last_sync_timestamp=now,
            error_message=error_message,
        )
        self.session.add(new_state)
        await self.session.flush()
        await self.session.refresh(new_state)
        return new_state
