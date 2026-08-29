"""Tenant-isolated, high-performance ingestion deduplication engine."""

from __future__ import annotations

import hashlib
import threading
import time
from datetime import UTC, datetime, timedelta
from typing import Any
from uuid import UUID

from src.ingestion_gateway.models import IngestionDedupRecordDTO
from src.utils.logging import get_logger

logger = get_logger(__name__)


class IngestionDeduplicationEngine:
    """Thread-safe, sliding-window deduplication engine ensuring zero duplicate message processing."""

    def __init__(self, default_ttl_sec: int = 86400) -> None:
        self.default_ttl_sec = default_ttl_sec
        self._lock = threading.RLock()
        # Key: dedup_key_str -> (record: IngestionDedupRecordDTO, expiry_timestamp_float)
        self._store: dict[str, tuple[IngestionDedupRecordDTO, float]] = {}
        self._total_checked: int = 0
        self._total_duplicates: int = 0

    @staticmethod
    def compute_dedup_key(
        tenant_id: UUID, account_id: UUID, provider_message_id: str
    ) -> str:
        """Compute deterministic SHA-256 canonical deduplication hash."""
        raw_seed = f"{tenant_id}:{account_id}:{provider_message_id.strip()}"
        return hashlib.sha256(raw_seed.encode("utf-8")).hexdigest()

    def is_duplicate(
        self, tenant_id: UUID, account_id: UUID, provider_message_id: str
    ) -> bool:
        """Check if message has already been ingested without marking it seen."""
        key = self.compute_dedup_key(tenant_id, account_id, provider_message_id)
        now = time.time()

        with self._lock:
            if key in self._store:
                _, expiry = self._store[key]
                if now < expiry:
                    return True
                # Expired entry
                del self._store[key]
            return False

    def mark_seen(
        self,
        tenant_id: UUID,
        account_id: UUID,
        provider_message_id: str,
        ttl_sec: int | None = None,
    ) -> bool:
        """Explicitly record a message as ingested. Returns True on success."""
        key = self.compute_dedup_key(tenant_id, account_id, provider_message_id)
        ttl = ttl_sec if ttl_sec is not None else self.default_ttl_sec
        now_ts = time.time()
        expiry_ts = now_ts + ttl

        now_dt = datetime.now(UTC)
        expires_dt = now_dt + timedelta(seconds=ttl)

        record = IngestionDedupRecordDTO(
            dedup_key=key,
            tenant_id=tenant_id,
            account_id=account_id,
            provider_message_id=provider_message_id.strip(),
            ingested_at=now_dt,
            expires_at=expires_dt,
        )

        with self._lock:
            self._store[key] = (record, expiry_ts)
            return True

    def check_and_mark(
        self,
        tenant_id: UUID,
        account_id: UUID,
        provider_message_id: str,
        ttl_sec: int | None = None,
    ) -> bool:
        """Atomically check if message is duplicate and mark it seen if new.

        Returns:
            True if message is NEW (successfully marked seen).
            False if message is a DUPLICATE (suppressed).
        """
        key = self.compute_dedup_key(tenant_id, account_id, provider_message_id)
        now_ts = time.time()
        ttl = ttl_sec if ttl_sec is not None else self.default_ttl_sec
        expiry_ts = now_ts + ttl

        with self._lock:
            self._total_checked += 1
            if key in self._store:
                _, existing_expiry = self._store[key]
                if now_ts < existing_expiry:
                    self._total_duplicates += 1
                    logger.debug(
                        "Deduplication hit for tenant %s, account %s, msg %s",
                        tenant_id,
                        account_id,
                        provider_message_id,
                    )
                    return False

            now_dt = datetime.now(UTC)
            expires_dt = now_dt + timedelta(seconds=ttl)
            record = IngestionDedupRecordDTO(
                dedup_key=key,
                tenant_id=tenant_id,
                account_id=account_id,
                provider_message_id=provider_message_id.strip(),
                ingested_at=now_dt,
                expires_at=expires_dt,
            )
            self._store[key] = (record, expiry_ts)
            return True

    def get_record(
        self, tenant_id: UUID, account_id: UUID, provider_message_id: str
    ) -> IngestionDedupRecordDTO | None:
        """Retrieve deduplication record if active."""
        key = self.compute_dedup_key(tenant_id, account_id, provider_message_id)
        now = time.time()

        with self._lock:
            if key in self._store:
                rec, expiry = self._store[key]
                if now < expiry:
                    return rec
                del self._store[key]
            return None

    def prune_expired(self) -> int:
        """Evict all expired deduplication records. Returns count of pruned records."""
        now = time.time()
        pruned = 0
        with self._lock:
            expired_keys = [k for k, (_, exp) in self._store.items() if now >= exp]
            for k in expired_keys:
                del self._store[k]
                pruned += 1
        return pruned

    def clear(self, tenant_id: UUID | None = None) -> None:
        """Clear cache. If tenant_id provided, only clears keys for that tenant."""
        with self._lock:
            if tenant_id is None:
                self._store.clear()
            else:
                target_keys = [
                    k for k, (rec, _) in self._store.items() if rec.tenant_id == tenant_id
                ]
                for k in target_keys:
                    del self._store[k]

    def get_stats(self) -> dict[str, Any]:
        """Return operational cache telemetry metrics."""
        with self._lock:
            return {
                "active_records_count": len(self._store),
                "total_checked": self._total_checked,
                "total_duplicates_suppressed": self._total_duplicates,
                "default_ttl_sec": self.default_ttl_sec,
            }
