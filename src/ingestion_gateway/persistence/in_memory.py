"""In-memory Storage Adapter for Dead-Letter Queue (Module 22)."""

from __future__ import annotations

import threading
from collections import deque
from uuid import UUID

from src.ingestion_gateway.dead_letter import DeadLetterItemDTO
from src.ingestion_gateway.persistence.base import IDeadLetterStorage


class InMemoryDeadLetterStorage(IDeadLetterStorage):
    """Thread-safe, bounded in-memory implementation of IDeadLetterStorage."""

    def __init__(self, max_items: int = 1000) -> None:
        self.max_items = max_items
        self._lock = threading.RLock()
        self._queue: deque[UUID] = deque(maxlen=max_items)
        self._items: dict[UUID, DeadLetterItemDTO] = {}

    def save(self, item: DeadLetterItemDTO) -> None:
        with self._lock:
            # If at capacity and item is new, pop oldest to maintain ring buffer bound
            if item.dead_letter_id not in self._items and len(self._queue) == self.max_items and self._queue:
                oldest_id = self._queue[0]
                if oldest_id in self._items:
                    del self._items[oldest_id]

            if item.dead_letter_id not in self._items:
                self._queue.append(item.dead_letter_id)
            self._items[item.dead_letter_id] = item

    def get(self, dead_letter_id: UUID) -> DeadLetterItemDTO | None:
        with self._lock:
            return self._items.get(dead_letter_id)

    def list_items(
        self, tenant_id: UUID | None = None, limit: int = 50
    ) -> list[DeadLetterItemDTO]:
        with self._lock:
            if tenant_id is None:
                return list(self._items.values())[:limit]
            return [
                item for item in self._items.values() if item.tenant_id == tenant_id
            ][:limit]

    def delete(self, dead_letter_id: UUID) -> bool:
        with self._lock:
            if dead_letter_id in self._items:
                del self._items[dead_letter_id]
                try:
                    self._queue.remove(dead_letter_id)
                except ValueError:
                    pass
                return True
            return False

    def clear_tenant(self, tenant_id: UUID) -> int:
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
            return len(target_ids)

    def count(self, tenant_id: UUID | None = None) -> int:
        with self._lock:
            if tenant_id is None:
                return len(self._items)
            return sum(1 for item in self._items.values() if item.tenant_id == tenant_id)
