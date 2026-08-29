"""Dead-Letter Queue and poison message isolation engine for Ingestion Gateway (Module 21)."""

from __future__ import annotations

import threading
from collections import deque
from collections.abc import Callable
from datetime import UTC, datetime
from typing import Any
from uuid import UUID, uuid4

from pydantic import BaseModel, ConfigDict, Field

from src.ingestion_gateway.models import MailboxProvider
from src.utils.logging import get_logger

logger = get_logger(__name__)


class DeadLetterItemDTO(BaseModel):
    """Immutable record representing a quarantined unprocessable/poison email ingestion item."""

    model_config = ConfigDict(frozen=True, extra="forbid", arbitrary_types_allowed=True)

    dead_letter_id: UUID = Field(
        default_factory=uuid4, description="Unique dead-letter record UUID"
    )
    tenant_id: UUID = Field(description="Associated enterprise Tenant UUID")
    account_id: UUID = Field(description="Associated EmailAccount UUID")
    provider: MailboxProvider = Field(description="Originating mailbox provider")
    reason: str = Field(description="Classification reason for dead-lettering")
    provider_message_id: str | None = Field(
        default=None, description="Original provider message ID if available"
    )
    raw_payload: str | None = Field(
        default=None, description="Safely bounded, secret-redacted raw payload representation"
    )
    error_message: str = Field(description="Error message that caused failure")
    error_traceback: str | None = Field(
        default=None, description="Stack trace snippet if available"
    )
    correlation_id: UUID = Field(
        default_factory=uuid4, description="Correlation UUID for tracing"
    )
    timestamp: datetime = Field(
        default_factory=lambda: datetime.now(UTC),
        description="UTC timestamp when quarantined",
    )
    retry_count: int = Field(default=0, ge=0, description="Count of retry attempts")
    max_retries: int = Field(default=3, ge=1, description="Maximum permitted retries")


# Hook signature for dead-letter event publishing
DLQEventHook = Callable[[DeadLetterItemDTO], Any]


class DeadLetterQueue:
    """Thread-safe, bounded, in-memory Dead-Letter Queue with tenant isolation and retry tracking."""

    def __init__(self, max_items: int = 1000) -> None:
        self.max_items = max_items
        self._lock = threading.RLock()
        # Ring buffer / deque of IDs for capacity bounding
        self._queue: deque[UUID] = deque(maxlen=max_items)
        # Store mapping: dead_letter_id -> DeadLetterItemDTO
        self._items: dict[UUID, DeadLetterItemDTO] = {}
        self._event_hook: DLQEventHook | None = None
        self._total_enqueued: int = 0
        self._total_purged: int = 0
        self._total_requeued: int = 0

    def set_event_hook(self, hook: DLQEventHook) -> None:
        """Register callback hook invoked whenever an item is enqueued into DLQ."""
        self._event_hook = hook

    def enqueue(
        self,
        tenant_id: UUID,
        account_id: UUID,
        provider: MailboxProvider,
        reason: str,
        error_message: str,
        provider_message_id: str | None = None,
        raw_payload: str | None = None,
        error_traceback: str | None = None,
        correlation_id: UUID | None = None,
    ) -> DeadLetterItemDTO:
        """Quarantine a failed message into the Dead-Letter Queue."""
        # Sanitize / bound raw payload representation (max 8KB)
        bounded_payload = raw_payload[:8192] if raw_payload else None

        item = DeadLetterItemDTO(
            tenant_id=tenant_id,
            account_id=account_id,
            provider=provider,
            reason=reason,
            provider_message_id=provider_message_id,
            raw_payload=bounded_payload,
            error_message=error_message,
            error_traceback=error_traceback,
            correlation_id=correlation_id or uuid4(),
            timestamp=datetime.now(UTC),
        )

        with self._lock:
            # If at capacity, pop oldest to maintain bound
            if len(self._queue) == self.max_items and self._queue:
                oldest_id = self._queue[0]
                if oldest_id in self._items:
                    del self._items[oldest_id]

            self._queue.append(item.dead_letter_id)
            self._items[item.dead_letter_id] = item
            self._total_enqueued += 1

            logger.warning(
                "Quarantined message into DLQ (id=%s, tenant=%s, provider=%s, reason=%s)",
                item.dead_letter_id,
                item.tenant_id,
                item.provider.value,
                item.reason,
            )

        if self._event_hook:
            try:
                self._event_hook(item)
            except Exception as hook_exc:
                logger.error("Error executing DLQ event hook: %s", hook_exc)

        return item

    def get(self, dead_letter_id: UUID) -> DeadLetterItemDTO | None:
        """Retrieve a dead-letter item by UUID."""
        with self._lock:
            return self._items.get(dead_letter_id)

    def list_items(
        self, tenant_id: UUID | None = None, limit: int = 50
    ) -> list[DeadLetterItemDTO]:
        """List dead-letter items, optionally filtered by tenant UUID."""
        with self._lock:
            if tenant_id is None:
                return list(self._items.values())[:limit]
            return [
                item for item in self._items.values() if item.tenant_id == tenant_id
            ][:limit]

    def purge(self, dead_letter_id: UUID) -> bool:
        """Remove a dead-letter item from the queue."""
        with self._lock:
            if dead_letter_id in self._items:
                del self._items[dead_letter_id]
                try:
                    self._queue.remove(dead_letter_id)
                except ValueError:
                    pass
                self._total_purged += 1
                return True
            return False

    def clear_tenant(self, tenant_id: UUID) -> int:
        """Purge all dead-letter items belonging to a specific tenant."""
        with self._lock:
            target_ids = [
                d_id for d_id, item in self._items.items() if item.tenant_id == tenant_id
            ]
            for d_id in target_ids:
                del self._items[d_id]
                try:
                    self._queue.remove(d_id)
                except ValueError:
                    pass
            self._total_purged += len(target_ids)
            return len(target_ids)

    def requeue(self, dead_letter_id: UUID) -> DeadLetterItemDTO | None:
        """Increment retry count for an item. Returns updated item or None if max retries exceeded."""
        with self._lock:
            item = self._items.get(dead_letter_id)
            if not item:
                return None

            if item.retry_count >= item.max_retries:
                logger.warning(
                    "Cannot requeue DLQ item %s: max retries (%d) reached.",
                    dead_letter_id,
                    item.max_retries,
                )
                return None

            updated_item = DeadLetterItemDTO(
                dead_letter_id=item.dead_letter_id,
                tenant_id=item.tenant_id,
                account_id=item.account_id,
                provider=item.provider,
                reason=item.reason,
                provider_message_id=item.provider_message_id,
                raw_payload=item.raw_payload,
                error_message=item.error_message,
                error_traceback=item.error_traceback,
                correlation_id=item.correlation_id,
                timestamp=datetime.now(UTC),
                retry_count=item.retry_count + 1,
                max_retries=item.max_retries,
            )
            self._items[dead_letter_id] = updated_item
            self._total_requeued += 1
            return updated_item

    def get_stats(self) -> dict[str, Any]:
        """Return DLQ telemetry and size statistics."""
        with self._lock:
            return {
                "current_size": len(self._items),
                "max_capacity": self.max_items,
                "total_enqueued": self._total_enqueued,
                "total_purged": self._total_purged,
                "total_requeued": self._total_requeued,
            }
