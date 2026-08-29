"""File-backed Persistent Storage Adapter for Dead-Letter Queue (Module 22)."""

from __future__ import annotations

import json
import os
import threading
from pathlib import Path
from uuid import UUID

from src.ingestion_gateway.dead_letter import DeadLetterItemDTO
from src.ingestion_gateway.persistence.base import IDeadLetterStorage
from src.utils.logging import get_logger

logger = get_logger(__name__)


class FileBackedDeadLetterStorage(IDeadLetterStorage):
    """Thread-safe, file-backed JSON persistent storage for Dead-Letter Queue records."""

    def __init__(self, storage_dir: Path | str, max_items: int = 1000) -> None:
        self.storage_dir = Path(storage_dir)
        self.max_items = max_items
        self._lock = threading.RLock()
        self.storage_dir.mkdir(parents=True, exist_ok=True)

    def _get_file_path(self, dead_letter_id: UUID) -> Path:
        return self.storage_dir / f"dlq_{dead_letter_id}.json"

    def save(self, item: DeadLetterItemDTO) -> None:
        with self._lock:
            # Enforce max capacity bounding
            existing_files = list(self.storage_dir.glob("dlq_*.json"))
            target_path = self._get_file_path(item.dead_letter_id)

            if not target_path.exists() and len(existing_files) >= self.max_items:
                # Remove oldest file based on mtime
                existing_files.sort(key=os.path.getmtime)
                oldest_file = existing_files[0]
                try:
                    oldest_file.unlink(missing_ok=True)
                except Exception as exc:
                    logger.warning("Failed to evict oldest DLQ file %s: %s", oldest_file, exc)

            # Write JSON atomically
            temp_path = self.storage_dir / f"tmp_{item.dead_letter_id}.tmp"
            payload_json = item.model_dump_json(indent=2)
            temp_path.write_text(payload_json, encoding="utf-8")
            temp_path.replace(target_path)

    def get(self, dead_letter_id: UUID) -> DeadLetterItemDTO | None:
        with self._lock:
            file_path = self._get_file_path(dead_letter_id)
            if not file_path.exists():
                return None
            try:
                content = file_path.read_text(encoding="utf-8")
                return DeadLetterItemDTO.model_validate_json(content)
            except Exception as exc:
                logger.error("Failed to load DLQ record from %s: %s", file_path, exc)
                return None

    def list_items(
        self, tenant_id: UUID | None = None, limit: int = 50
    ) -> list[DeadLetterItemDTO]:
        with self._lock:
            items: list[DeadLetterItemDTO] = []
            files = sorted(
                self.storage_dir.glob("dlq_*.json"),
                key=os.path.getmtime,
                reverse=True,
            )

            for f in files:
                try:
                    content = f.read_text(encoding="utf-8")
                    dto = DeadLetterItemDTO.model_validate_json(content)
                    if tenant_id is None or dto.tenant_id == tenant_id:
                        items.append(dto)
                        if len(items) >= limit:
                            break
                except Exception as exc:
                    logger.warning("Skipping corrupted DLQ file %s: %s", f, exc)

            return items

    def delete(self, dead_letter_id: UUID) -> bool:
        with self._lock:
            file_path = self._get_file_path(dead_letter_id)
            if file_path.exists():
                try:
                    file_path.unlink()
                    return True
                except Exception as exc:
                    logger.error("Failed to delete DLQ file %s: %s", file_path, exc)
                    return False
            return False

    def clear_tenant(self, tenant_id: UUID) -> int:
        with self._lock:
            deleted_count = 0
            for f in list(self.storage_dir.glob("dlq_*.json")):
                try:
                    content = f.read_text(encoding="utf-8")
                    data = json.loads(content)
                    if data.get("tenant_id") == str(tenant_id):
                        f.unlink()
                        deleted_count += 1
                except Exception as exc:
                    logger.warning("Error clearing tenant from %s: %s", f, exc)
            return deleted_count

    def count(self, tenant_id: UUID | None = None) -> int:
        with self._lock:
            if tenant_id is None:
                return len(list(self.storage_dir.glob("dlq_*.json")))
            return len(self.list_items(tenant_id=tenant_id, limit=self.max_items))
