"""Abstract Storage Interface for Persistent Dead-Letter Queue (Module 22)."""

from __future__ import annotations

from abc import ABC, abstractmethod
from uuid import UUID

from src.ingestion_gateway.dead_letter import DeadLetterItemDTO


class IDeadLetterStorage(ABC):
    """Abstract interface defining the contract for Dead-Letter Queue persistent storage."""

    @abstractmethod
    def save(self, item: DeadLetterItemDTO) -> None:
        """Persist or update a DeadLetterItemDTO."""
        ...

    @abstractmethod
    def get(self, dead_letter_id: UUID) -> DeadLetterItemDTO | None:
        """Retrieve a specific DeadLetterItemDTO by ID."""
        ...

    @abstractmethod
    def list_items(
        self, tenant_id: UUID | None = None, limit: int = 50
    ) -> list[DeadLetterItemDTO]:
        """List dead-letter items, optionally filtered by tenant UUID, up to limit."""
        ...

    @abstractmethod
    def delete(self, dead_letter_id: UUID) -> bool:
        """Remove a dead-letter item from storage. Returns True if deleted."""
        ...

    @abstractmethod
    def clear_tenant(self, tenant_id: UUID) -> int:
        """Remove all dead-letter items for a specific tenant. Returns count deleted."""
        ...

    @abstractmethod
    def count(self, tenant_id: UUID | None = None) -> int:
        """Return total count of stored items, optionally filtered by tenant."""
        ...
