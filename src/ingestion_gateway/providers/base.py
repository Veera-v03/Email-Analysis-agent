"""Abstract base class interface protocol for asynchronous mailbox ingestion daemons."""

from __future__ import annotations

from abc import ABC, abstractmethod
from collections.abc import Awaitable, Callable
from datetime import UTC, datetime
from typing import Any
from uuid import UUID, uuid4

from src.ingestion_gateway.models import (
    DaemonStatus,
    IngestedEmailDTO,
    IngestionMode,
    MailboxDaemonStateDTO,
    MailboxProvider,
)
from src.utils.logging import get_logger

logger = get_logger(__name__)

# Delivery callback type definition
DeliveryHandler = Callable[[IngestedEmailDTO], Awaitable[None]]


class IAsyncMailboxDaemon(ABC):
    """Abstract asynchronous daemon interface for continuous mailbox monitoring and ingestion."""

    def __init__(
        self,
        tenant_id: UUID,
        account_id: UUID,
        mailbox_address: str,
        mode: IngestionMode = IngestionMode.POLLING,
    ) -> None:
        self.daemon_id: UUID = uuid4()
        self.tenant_id: UUID = tenant_id
        self.account_id: UUID = account_id
        self.mailbox_address: str = mailbox_address
        self.mode: IngestionMode = mode
        self._status: DaemonStatus = DaemonStatus.STOPPED
        self._messages_ingested: int = 0
        self._last_activity_at: datetime = datetime.now(UTC)
        self._error_message: str | None = None
        self._delivery_handler: DeliveryHandler | None = None

    @property
    @abstractmethod
    def provider(self) -> MailboxProvider:
        """Provider enumeration identifier."""

    @property
    def status(self) -> DaemonStatus:
        """Current operational status."""
        return self._status

    @property
    def messages_ingested(self) -> int:
        """Total successfully ingested message count."""
        return self._messages_ingested

    def set_delivery_handler(self, handler: DeliveryHandler) -> None:
        """Register asynchronous callback handler invoked when new emails are normalized."""
        self._delivery_handler = handler

    async def deliver(self, email: IngestedEmailDTO) -> None:
        """Deliver normalized email to downstream handler and update daemon metrics."""
        self._messages_ingested += 1
        self._last_activity_at = datetime.now(UTC)

        if self._delivery_handler:
            try:
                await self._delivery_handler(email)
            except Exception as exc:
                logger.error(
                    "Error executing delivery handler for message %s in daemon %s: %s",
                    email.provider_message_id,
                    self.daemon_id,
                    exc,
                )
                raise

    def get_state(self) -> MailboxDaemonStateDTO:
        """Export snapshot of daemon operational metrics."""
        return MailboxDaemonStateDTO(
            daemon_id=self.daemon_id,
            tenant_id=self.tenant_id,
            account_id=self.account_id,
            provider=self.provider,
            mailbox_address=self.mailbox_address,
            status=self._status,
            mode=self.mode,
            messages_ingested=self._messages_ingested,
            last_activity_at=self._last_activity_at,
            error_message=self._error_message,
        )

    @abstractmethod
    async def start(self) -> None:
        """Initialize connection, establish subscriptions/loops, and begin ingestion."""

    @abstractmethod
    async def stop(self) -> None:
        """Gracefully disconnect, cancel background workers, and flush pending state."""

    @abstractmethod
    async def health_check(self) -> dict[str, Any]:
        """Perform diagnostic health check probing connection and credentials."""
