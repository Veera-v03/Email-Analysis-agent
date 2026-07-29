"""Memory management module for TTL retention, cleanup, deduplication, and statistics."""

from __future__ import annotations

from datetime import UTC, datetime

from src.memory.models.memory_models import MemoryStats
from src.memory.storage.vector_store import IVectorStore


class MemoryManager:
    """Manages memory retention lifecycle, periodic cleanup, deduplication, and stats."""

    def __init__(self, vector_store: IVectorStore) -> None:
        self._store = vector_store

    def cleanup_expired_records(self) -> int:
        """Purge records whose age exceeds their configured ttl_seconds. Returns deleted count."""
        now_dt = datetime.now(UTC)
        deleted_count = 0

        # We inspect stored records
        records_to_delete: list[str] = []

        # Access internal store records if available
        if hasattr(self._store, "_records"):
            store_records = getattr(self._store, "_records")
            for memory_id, record in list(store_records.items()):
                if record.ttl_seconds is not None:
                    try:
                        created_dt = datetime.fromisoformat(record.created_at)
                        age_seconds = (now_dt - created_dt).total_seconds()
                        if age_seconds > record.ttl_seconds:
                            records_to_delete.append(memory_id)
                    except Exception:
                        pass

        for mid in records_to_delete:
            if self._store.delete(mid):
                deleted_count += 1

        return deleted_count

    def deduplicate(self) -> int:
        """Identify and delete duplicate records possessing identical content vectors. Returns count."""
        deleted_count = 0
        if hasattr(self._store, "_records"):
            store_records = getattr(self._store, "_records")
            seen_vectors: set[tuple[float, ...]] = set()
            duplicates: list[str] = []

            for memory_id, record in list(store_records.items()):
                if record.vector and record.vector in seen_vectors:
                    duplicates.append(memory_id)
                elif record.vector:
                    seen_vectors.add(record.vector)

            for mid in duplicates:
                if self._store.delete(mid):
                    deleted_count += 1

        return deleted_count

    def get_stats(self) -> MemoryStats:
        """Compute aggregated operational metrics of the memory store."""
        total_count = self._store.count()
        type_counts: dict[str, int] = {}
        oldest_ts: str | None = None
        newest_ts: str | None = None
        estimated_bytes = 0

        if hasattr(self._store, "_records"):
            store_records = getattr(self._store, "_records")
            timestamps: list[str] = []

            for record in store_records.values():
                mtype = record.memory_type.value
                type_counts[mtype] = type_counts.get(mtype, 0) + 1
                timestamps.append(record.created_at)
                estimated_bytes += len(str(record.model_dump()))

            if timestamps:
                timestamps.sort()
                oldest_ts = timestamps[0]
                newest_ts = timestamps[-1]

        return MemoryStats(
            total_records=total_count,
            type_counts=type_counts,
            storage_bytes=estimated_bytes,
            oldest_timestamp=oldest_ts,
            newest_timestamp=newest_ts,
        )
