"""Strongly typed DTO schemas and enumerations for Ingestion Gateway."""

from __future__ import annotations

from datetime import UTC, datetime
from enum import StrEnum
from typing import Any
from uuid import UUID, uuid4

from pydantic import BaseModel, ConfigDict, Field, model_validator


class MailboxProvider(StrEnum):
    """Supported enterprise email mailbox providers."""

    MS_GRAPH = "MS_GRAPH"
    GMAIL = "GMAIL"
    IMAP = "IMAP"


class DaemonStatus(StrEnum):
    """Operational lifecycle state of a mailbox ingestion daemon."""

    STARTING = "STARTING"
    RUNNING = "RUNNING"
    STOPPED = "STOPPED"
    DEGRADED = "DEGRADED"
    ERROR = "ERROR"


class IngestionMode(StrEnum):
    """Active ingestion delivery mode."""

    WEBHOOK = "WEBHOOK"
    POLLING = "POLLING"
    IDLE = "IDLE"


class IngestedEmailDTO(BaseModel):
    """Canonical normalized email payload produced by live ingestion gateway before pipeline handoff."""

    model_config = ConfigDict(
        frozen=True,
        extra="forbid",
        arbitrary_types_allowed=True,
    )

    ingestion_id: UUID = Field(
        default_factory=uuid4, description="Unique ingestion event UUID"
    )
    tenant_id: UUID = Field(description="Associated enterprise Tenant UUID")
    account_id: UUID = Field(description="Associated EmailAccount UUID")
    mailbox_address: str = Field(description="Monitored mailbox email address")
    provider: MailboxProvider = Field(description="Source mailbox provider type")
    provider_message_id: str = Field(
        description="Provider-specific message identifier (e.g. Graph ID, Gmail ID, IMAP UID)"
    )
    internet_message_id: str | None = Field(
        default=None, description="RFC 5322 Message-ID header if available"
    )
    sender: str = Field(description="Envelope or header sender address")
    recipients: list[str] = Field(
        default_factory=list, description="Target recipient email addresses"
    )
    subject: str = Field(default="", description="Email subject line")
    received_at: datetime = Field(
        default_factory=lambda: datetime.now(UTC),
        description="Timestamp of email receipt in UTC",
    )
    raw_eml_bytes: bytes = Field(
        ..., description="Raw unparsed RFC 5322 EML byte payload"
    )
    raw_size_bytes: int = Field(
        default=0, description="Size of raw EML payload in bytes"
    )
    correlation_id: UUID = Field(
        default_factory=uuid4,
        description="Distributed correlation ID for end-to-end tracing",
    )

    @model_validator(mode="before")
    @classmethod
    def _calculate_size_and_validate(cls, data: Any) -> Any:
        if isinstance(data, dict):
            raw_bytes = data.get("raw_eml_bytes")
            if isinstance(raw_bytes, bytes) and not data.get("raw_size_bytes"):
                data["raw_size_bytes"] = len(raw_bytes)
        return data

    def to_raw_email(self) -> Any:
        """Convert canonical DTO into RawEmail database/pipeline entity."""
        from src.database.models import RawEmail

        return RawEmail(
            id=self.ingestion_id,
            tenant_id=self.tenant_id,
            account_id=self.account_id,
            raw_eml_data=self.raw_eml_bytes,
            raw_size_bytes=self.raw_size_bytes,
            message_id=self.provider_message_id,
            internet_message_id=self.internet_message_id or "",
            created_at=self.received_at,
        )


class MailboxDaemonStateDTO(BaseModel):
    """Real-time operational state metrics for an active mailbox daemon worker."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    daemon_id: UUID = Field(default_factory=uuid4, description="Daemon instance UUID")
    tenant_id: UUID = Field(description="Associated Tenant UUID")
    account_id: UUID = Field(description="Associated EmailAccount UUID")
    provider: MailboxProvider = Field(description="Mailbox provider type")
    mailbox_address: str = Field(description="Target mailbox address")
    status: DaemonStatus = Field(default=DaemonStatus.STOPPED, description="Current lifecycle state")
    mode: IngestionMode = Field(default=IngestionMode.POLLING, description="Ingestion mechanism")
    messages_ingested: int = Field(default=0, ge=0, description="Total count of successfully ingested messages")
    last_activity_at: datetime = Field(
        default_factory=lambda: datetime.now(UTC),
        description="UTC timestamp of last sync/event activity",
    )
    error_message: str | None = Field(default=None, description="Last recorded error string if degraded/error")


class IngestionDedupRecordDTO(BaseModel):
    """Audit record for a deduplicated message identifier."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    dedup_key: str = Field(description="SHA-256 canonical hash of tenant:account:provider_message_id")
    tenant_id: UUID = Field(description="Associated Tenant UUID")
    account_id: UUID = Field(description="Associated EmailAccount UUID")
    provider_message_id: str = Field(description="Original provider message ID")
    ingested_at: datetime = Field(
        default_factory=lambda: datetime.now(UTC),
        description="Timestamp when message was first observed",
    )
    expires_at: datetime = Field(description="Timestamp when deduplication record expires")
