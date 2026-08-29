"""Dead-Letter Queue persistence adapters and storage contracts (Module 22)."""

from __future__ import annotations

from src.ingestion_gateway.persistence.base import IDeadLetterStorage
from src.ingestion_gateway.persistence.file_storage import FileBackedDeadLetterStorage
from src.ingestion_gateway.persistence.in_memory import InMemoryDeadLetterStorage

__all__ = [
    "IDeadLetterStorage",
    "InMemoryDeadLetterStorage",
    "FileBackedDeadLetterStorage",
]
