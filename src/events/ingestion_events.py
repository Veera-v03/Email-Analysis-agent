"""Email Ingestion event contract payloads matching SAS v1.1.0."""

from __future__ import annotations

from datetime import UTC, datetime
from uuid import UUID

from pydantic import Field

from src.events.base_event import BaseEvent


class EmailReceivedEvent(BaseEvent):
    """Event emitted when a new email is detected via Watch/Webhook or History API."""

    event_type: str = "scamon.prod.ingestion.email.received.v1"
    account_id: UUID = Field(description="Associated EmailAccount UUID")
    message_id: str = Field(description="Provider message ID string")
    history_id: str | None = Field(
        default=None, description="Gmail History ID if available"
    )
    provider: str = Field(description="Ingestion provider: GMAIL or MS_GRAPH")


class EmailDownloadedEvent(BaseEvent):
    """Event emitted when raw EML and metadata are downloaded and saved to database."""

    event_type: str = "scamon.prod.ingestion.email.downloaded.v1"
    account_id: UUID = Field(description="Associated EmailAccount UUID")
    raw_email_id: UUID = Field(description="RawEmail record UUID")
    message_id: str = Field(description="Provider message ID string")
    internet_message_id: str = Field(description="RFC 5322 Message-ID header value")
    sender_address: str = Field(description="Sender email address")
    recipient_addresses: list[str] = Field(
        default_factory=list, description="Recipient email addresses"
    )
    subject: str = Field(default="", description="Email subject")
    received_at: datetime = Field(
        default_factory=lambda: datetime.now(UTC),
        description="Original email receipt timestamp",
    )
    raw_size_bytes: int = Field(default=0, description="Raw EML size in bytes")


class MailboxSyncCompletedEvent(BaseEvent):
    """Event emitted when initial or incremental mailbox synchronization completes."""

    event_type: str = "scamon.prod.ingestion.sync.completed.v1"
    account_id: UUID = Field(description="Associated EmailAccount UUID")
    sync_type: str = Field(description="Sync mode: INITIAL or INCREMENTAL")
    emails_processed: int = Field(description="Count of emails processed")
    latest_history_id: str | None = Field(
        default=None, description="Updated history ID"
    )


class MailboxSyncFailedEvent(BaseEvent):
    """Event emitted when mailbox synchronization encounters an error."""

    event_type: str = "scamon.prod.ingestion.sync.failed.v1"
    account_id: UUID = Field(description="Associated EmailAccount UUID")
    error_message: str = Field(description="Failure description")
