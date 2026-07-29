"""Vector storage abstraction and thread-safe in-memory vector store implementation."""

from __future__ import annotations

import json
import math
from abc import ABC, abstractmethod
from pathlib import Path
from typing import Any

from src.memory.models.memory_models import (
    BaseMemoryRecord,
    MemorySearchResult,
    MemoryType,
)


class IVectorStore(ABC):
    """Abstract interface for vector database storage and similarity search."""

    @abstractmethod
    def insert(self, record: BaseMemoryRecord) -> None:
        """Insert a new memory record into the store."""

    @abstractmethod
    def update(self, record: BaseMemoryRecord) -> None:
        """Update an existing memory record in the store."""

    @abstractmethod
    def delete(self, memory_id: str) -> bool:
        """Delete a record by memory_id. Returns True if deleted."""

    @abstractmethod
    def get(self, memory_id: str) -> BaseMemoryRecord | None:
        """Fetch a record by memory_id."""

    @abstractmethod
    def similarity_search(
        self,
        query_vector: tuple[float, ...],
        top_k: int = 5,
        memory_type: MemoryType | None = None,
        min_confidence: float = 0.0,
        metadata_filters: dict[str, Any] | None = None,
    ) -> list[MemorySearchResult]:
        """Perform top-k similarity search using cosine similarity distance."""

    @abstractmethod
    def clear(self) -> None:
        """Clear all stored records."""

    @abstractmethod
    def count(self) -> int:
        """Return the total number of stored memory records."""


class InMemoryVectorStore(IVectorStore):
    """In-memory vector store with metadata filtering, cosine similarity, and snapshot persistence."""

    def __init__(self, persistence_file: Path | str | None = None) -> None:
        self._records: dict[str, BaseMemoryRecord] = {}
        self._persistence_file = Path(persistence_file) if persistence_file else None
        if self._persistence_file and self._persistence_file.exists():
            self.restore()

    def insert(self, record: BaseMemoryRecord) -> None:
        """Insert or replace record."""
        self._records[record.memory_id] = record
        if self._persistence_file:
            self.snapshot()

    def update(self, record: BaseMemoryRecord) -> None:
        """Update existing record."""
        if record.memory_id not in self._records:
            raise KeyError(
                f"Record with memory_id '{record.memory_id}' does not exist."
            )
        self._records[record.memory_id] = record
        if self._persistence_file:
            self.snapshot()

    def delete(self, memory_id: str) -> bool:
        """Delete record if present."""
        if memory_id in self._records:
            del self._records[memory_id]
            if self._persistence_file:
                self.snapshot()
            return True
        return False

    def get(self, memory_id: str) -> BaseMemoryRecord | None:
        """Get record by memory_id."""
        return self._records.get(memory_id)

    def count(self) -> int:
        """Return total record count."""
        return len(self._records)

    def clear(self) -> None:
        """Clear all stored records."""
        self._records.clear()
        if self._persistence_file and self._persistence_file.exists():
            self.snapshot()

    def similarity_search(
        self,
        query_vector: tuple[float, ...],
        top_k: int = 5,
        memory_type: MemoryType | None = None,
        min_confidence: float = 0.0,
        metadata_filters: dict[str, Any] | None = None,
    ) -> list[MemorySearchResult]:
        """Perform top-k cosine similarity search with type, confidence, and metadata filtering."""
        results: list[tuple[float, BaseMemoryRecord]] = []

        query_norm = math.sqrt(sum(q * q for q in query_vector))

        for record in self._records.values():
            # 1. Type filter
            if memory_type is not None and record.memory_type != memory_type:
                continue

            # 2. Confidence filter
            if record.confidence_score < min_confidence:
                continue

            # 3. Metadata filters
            if metadata_filters:
                match = True
                for k, v in metadata_filters.items():
                    if record.metadata.get(k) != v:
                        match = False
                        break
                if not match:
                    continue

            # 4. Vector cosine similarity computation
            rec_vec = record.vector
            if not rec_vec or not query_vector or len(rec_vec) != len(query_vector):
                sim = 0.0
            else:
                dot = sum(a * b for a, b in zip(query_vector, rec_vec))
                rec_norm = math.sqrt(sum(r * r for r in rec_vec))
                if query_norm > 0 and rec_norm > 0:
                    sim = dot / (query_norm * rec_norm)
                else:
                    sim = 0.0

            results.append((sim, record))

        # Sort by similarity score descending
        results.sort(key=lambda item: item[0], reverse=True)

        top_results = results[:top_k]
        return [
            MemorySearchResult(
                memory_id=rec.memory_id,
                memory_type=rec.memory_type,
                similarity_score=round(sim, 4),
                record=rec,
            )
            for sim, rec in top_results
        ]

    def snapshot(self) -> None:
        """Persist vector store contents to disk JSON snapshot."""
        if not self._persistence_file:
            return

        self._persistence_file.parent.mkdir(parents=True, exist_ok=True)
        dump_data = [rec.model_dump(mode="json") for rec in self._records.values()]
        with open(self._persistence_file, "w", encoding="utf-8") as f:
            json.dump(dump_data, f, indent=2)

    def restore(self) -> None:
        """Restore vector store contents from disk JSON snapshot."""
        if not self._persistence_file or not self._persistence_file.exists():
            return

        from src.memory.models.memory_models import (
            AttachmentMemory,
            CaseMemory,
            EvidenceMemory,
            InvestigationMemory,
            PatternMemory,
            SenderMemory,
            ThreatMemory,
            URLMemory,
        )

        type_map: dict[str, type[BaseMemoryRecord]] = {
            MemoryType.INVESTIGATION.value: InvestigationMemory,
            MemoryType.EVIDENCE.value: EvidenceMemory,
            MemoryType.THREAT.value: ThreatMemory,
            MemoryType.SENDER.value: SenderMemory,
            MemoryType.URL.value: URLMemory,
            MemoryType.ATTACHMENT.value: AttachmentMemory,
            MemoryType.PATTERN.value: PatternMemory,
            MemoryType.CASE.value: CaseMemory,
        }

        try:
            with open(self._persistence_file, encoding="utf-8") as f:
                data = json.load(f)
            self._records.clear()
            for item in data:
                mtype = item.get("memory_type")
                target_cls = type_map.get(mtype, BaseMemoryRecord)
                rec = target_cls.model_validate(item)
                self._records[rec.memory_id] = rec
        except Exception:
            pass  # Fallback to empty store if corrupt
