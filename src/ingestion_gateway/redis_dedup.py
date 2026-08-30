"""Tenant-isolated, distributed Redis atomic ingestion deduplication engine."""

from __future__ import annotations

import asyncio
from uuid import UUID

from src.common.redis_client import (
    AsyncRedisClient,
    InMemoryRedisClient,
    get_redis_client,
)
from src.ingestion_gateway.dedup import IngestionDeduplicationEngine
from src.utils.logging import get_logger

logger = get_logger("scamon.ingestion.redis_dedup")


class RedisIngestionDeduplicationEngine(IngestionDeduplicationEngine):
    """Distributed ingestion deduplication using atomic Redis SET NX EX commands with in-memory fallback."""

    def __init__(
        self,
        redis_client: AsyncRedisClient | InMemoryRedisClient | None = None,
        default_ttl_sec: int = 86400,
    ) -> None:
        super().__init__(default_ttl_sec=default_ttl_sec)
        self.redis_client = redis_client or get_redis_client()

    @staticmethod
    def compute_redis_key(
        tenant_id: UUID, account_id: UUID, provider_message_id: str
    ) -> str:
        """Compute tenant-scoped Redis deduplication key."""
        dedup_hash = IngestionDeduplicationEngine.compute_dedup_key(
            tenant_id, account_id, provider_message_id
        )
        return f"scamon:{tenant_id}:dedup:{account_id}:{dedup_hash}"

    async def is_duplicate_async(
        self, tenant_id: UUID, account_id: UUID, provider_message_id: str
    ) -> bool:
        """Asynchronously check if message exists in Redis without mutating TTL."""
        key = self.compute_redis_key(tenant_id, account_id, provider_message_id)
        try:
            exists = await self.redis_client.exists(key)
            return exists > 0
        except Exception as exc:
            logger.warning(
                "Redis dedup check error (%s); falling back to local memory store", exc
            )
            return self.is_duplicate(tenant_id, account_id, provider_message_id)

    async def mark_seen_async(
        self,
        tenant_id: UUID,
        account_id: UUID,
        provider_message_id: str,
        ttl_sec: int | None = None,
    ) -> bool:
        """Asynchronously record message in Redis."""
        key = self.compute_redis_key(tenant_id, account_id, provider_message_id)
        ttl = ttl_sec if ttl_sec is not None else self.default_ttl_sec
        try:
            # Value stores lightweight timestamp token (never raw email contents or credentials)
            return await self.redis_client.set(key, "1", ex=ttl)
        except Exception as exc:
            logger.warning(
                "Redis mark_seen error (%s); falling back to local memory store", exc
            )
            return self.mark_seen(
                tenant_id, account_id, provider_message_id, ttl_sec=ttl_sec
            )

    async def check_and_mark_async(
        self,
        tenant_id: UUID,
        account_id: UUID,
        provider_message_id: str,
        ttl_sec: int | None = None,
    ) -> bool:
        """Atomically check if message is duplicate and mark it seen using SET NX EX.

        Returns:
            True if message is NEW (successfully marked seen in Redis).
            False if message is DUPLICATE (suppressed).
        """
        key = self.compute_redis_key(tenant_id, account_id, provider_message_id)
        ttl = ttl_sec if ttl_sec is not None else self.default_ttl_sec
        try:
            is_new = await self.redis_client.set(key, "1", ex=ttl, nx=True)
            with self._lock:
                self._total_checked += 1
                if not is_new:
                    self._total_duplicates += 1
            return bool(is_new)
        except Exception as exc:
            logger.warning(
                "Redis atomic dedup error (%s); falling back to local memory store", exc
            )
            return self.check_and_mark(
                tenant_id, account_id, provider_message_id, ttl_sec=ttl_sec
            )
