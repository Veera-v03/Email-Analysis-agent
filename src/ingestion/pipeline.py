"""Email Ingestion Pipeline coordinating provider sync, DB storage, and event dispatching."""

from __future__ import annotations

import json
from uuid import UUID

from sqlalchemy.ext.asyncio import AsyncSession

from src.config.logging import get_logger
from src.database.models import (
    EmailAccount,
    EmailMetadataRecord,
    MailboxSyncState,
    RawEmail,
)
from src.database.repositories.email_account_repository import EmailAccountRepository
from src.database.repositories.mailbox_sync_repository import MailboxSyncStateRepository
from src.database.repositories.raw_email_repository import RawEmailRepository
from src.events.base_event import BaseEvent
from src.events.ingestion_events import (
    EmailDownloadedEvent,
    EmailReceivedEvent,
    MailboxSyncCompletedEvent,
    MailboxSyncFailedEvent,
)
from src.ingestion.exceptions import IngestionError, MailboxSyncError
from src.ingestion.interfaces import IEmailProvider
from src.ingestion.providers.gmail_provider import GmailProvider
from src.ingestion.providers.msgraph_provider import MicrosoftGraphProvider
from src.interfaces.event_publisher import IEventPublisher

logger = get_logger("scamon.ingestion.pipeline")


class IngestionPipeline:
    """Orchestrates multi-provider email ingestion, raw EML persistence, and event dispatching."""

    def __init__(self, event_publisher: IEventPublisher | None = None) -> None:
        self.event_publisher = event_publisher

    def resolve_provider(self, account: EmailAccount) -> IEmailProvider:
        """Instantiate concrete IEmailProvider for an EmailAccount entity."""
        provider_type = account.provider.upper()
        if provider_type == "GMAIL":
            return GmailProvider(
                access_token=account.access_token,
                refresh_token=account.refresh_token,
            )
        elif provider_type == "MS_GRAPH":
            return MicrosoftGraphProvider(
                access_token=account.access_token,
                refresh_token=account.refresh_token,
            )
        else:
            raise IngestionError(f"Unsupported ingestion provider: {account.provider}")

    async def run_initial_sync(
        self, session: AsyncSession, account_id: UUID, limit: int = 50
    ) -> int:
        """Execute initial mailbox synchronization for an EmailAccount."""
        account_repo = EmailAccountRepository(session)
        sync_repo = MailboxSyncStateRepository(session)
        raw_repo = RawEmailRepository(session)

        account = await account_repo.get_by_id(account_id)
        if not account or not account.is_active:
            raise MailboxSyncError(f"Active EmailAccount '{account_id}' not found")

        provider = self.resolve_provider(account)
        await sync_repo.update_sync_progress(account.id, status="SYNCING")

        try:
            message_summaries = await provider.fetch_initial_sync(limit=limit)
            processed_count = 0
            latest_hid: str | None = None

            for summary in message_summaries:
                msg_id = summary["id"]
                latest_hid = summary.get("historyId", latest_hid)

                # Emit EmailReceivedEvent
                await self._publish_event(
                    EmailReceivedEvent(
                        tenant_id=account.tenant_id,
                        account_id=account.id,
                        message_id=msg_id,
                        history_id=latest_hid,
                        provider=provider.provider_name,
                    )
                )

                # Fetch Raw EML and Metadata
                raw_eml = await provider.get_raw_eml(msg_id)
                meta = await provider.get_message_metadata(msg_id)

                # Check if raw email already exists
                existing = await raw_repo.get_by_message_id(account.id, msg_id)
                if not existing:
                    raw_record = RawEmail(
                        account_id=account.id,
                        tenant_id=account.tenant_id,
                        message_id=msg_id,
                        internet_message_id=meta["internet_message_id"],
                        raw_eml_data=raw_eml,
                        raw_size_bytes=len(raw_eml),
                    )
                    session.add(raw_record)
                    await session.flush()
                    await session.refresh(raw_record)

                    recipients_json = json.dumps(meta["recipient_addresses"])
                    meta_record = EmailMetadataRecord(
                        account_id=account.id,
                        tenant_id=account.tenant_id,
                        raw_email_id=raw_record.id,
                        message_id=msg_id,
                        internet_message_id=meta["internet_message_id"],
                        sender_address=meta["sender_address"],
                        recipient_addresses=recipients_json,
                        subject=meta["subject"],
                        has_attachments=meta.get("has_attachments", False),
                        attachment_count=meta.get("attachment_count", 0),
                    )
                    session.add(meta_record)
                    await session.flush()

                    processed_count += 1

                    # Emit EmailDownloadedEvent
                    await self._publish_event(
                        EmailDownloadedEvent(
                            tenant_id=account.tenant_id,
                            account_id=account.id,
                            raw_email_id=raw_record.id,
                            message_id=msg_id,
                            internet_message_id=meta["internet_message_id"],
                            sender_address=meta["sender_address"],
                            recipient_addresses=meta["recipient_addresses"],
                            subject=meta["subject"] or "",
                            raw_size_bytes=len(raw_eml),
                        )
                    )

            await sync_repo.update_sync_progress(
                account.id, status="IDLE", last_history_id=latest_hid
            )

            await self._publish_event(
                MailboxSyncCompletedEvent(
                    tenant_id=account.tenant_id,
                    account_id=account.id,
                    sync_type="INITIAL",
                    emails_processed=processed_count,
                    latest_history_id=latest_hid,
                )
            )
            logger.info(
                "Initial sync completed for account '%s': %d emails ingested",
                account.id,
                processed_count,
            )
            return processed_count

        except Exception as exc:
            logger.error("Mailbox sync failed for account '%s': %s", account.id, exc)
            await sync_repo.update_sync_progress(
                account.id, status="FAILED", error_message=str(exc)
            )
            await self._publish_event(
                MailboxSyncFailedEvent(
                    tenant_id=account.tenant_id,
                    account_id=account.id,
                    error_message=str(exc),
                )
            )
            raise MailboxSyncError(f"Mailbox sync failed: {exc}") from exc

    async def _publish_event(self, event: BaseEvent) -> None:
        """Safely publish an event if event publisher is configured."""
        if self.event_publisher:
            try:
                await self.event_publisher.publish(event)
            except Exception as exc:
                logger.error(
                    "Failed to publish ingestion event '%s': %s", event.event_type, exc
                )
