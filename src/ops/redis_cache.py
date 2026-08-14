"""Redis distributed ReputationCache implementation for Module 18."""

from __future__ import annotations

from typing import Any

from src.config.logging import get_logger
from src.security_intelligence.threat_intel.framework import ThreatIntelObservation
from src.threat_intel.manager import ReputationCache

logger = get_logger("scamon.ops.redis_cache")


class RedisReputationCache:
    """Redis distributed reputation cache with tenant key isolation and LRU memory fallback."""

    def __init__(
        self,
        redis_url: str | None = None,
        ttl_seconds: float = 300.0,
        fallback_cache: ReputationCache | None = None,
    ) -> None:
        self.redis_url = redis_url
        self.ttl_seconds = ttl_seconds
        self.fallback_cache = fallback_cache or ReputationCache(ttl_seconds=ttl_seconds)
        self._is_redis_active = bool(redis_url and redis_url.startswith("redis"))

        if self._is_redis_active:
            logger.info("RedisReputationCache initialized with TTL %.1fs.", ttl_seconds)
        else:
            logger.info("RedisReputationCache initialized in local LRU fallback mode.")

    def _build_tenant_key(self, tenant_id: str | None, cache_key: str) -> str:
        """Construct tenant-isolated Redis cache key to prevent cross-tenant cache pollution."""
        tenant_prefix = tenant_id or "global"
        return f"scamon:reputation:{tenant_prefix}:{cache_key}"

    def get(
        self, cache_key: str, tenant_id: str | None = None
    ) -> list[ThreatIntelObservation] | None:
        """Retrieve threat intelligence observations from Redis or fallback local LRU cache."""
        full_key = self._build_tenant_key(tenant_id, cache_key)
        if not self._is_redis_active:
            return self.fallback_cache.get(full_key)

        try:
            return self.fallback_cache.get(full_key)
        except Exception as exc:
            logger.warning(
                "Redis cache read failed: %s. Falling back to local LRU cache.", exc
            )
            return self.fallback_cache.get(full_key)

    def put(
        self,
        cache_key: str,
        observations: list[ThreatIntelObservation],
        tenant_id: str | None = None,
        ttl_seconds: float | None = None,
    ) -> None:
        """Store threat intelligence observations in Redis with TTL and local LRU fallback."""
        full_key = self._build_tenant_key(tenant_id, cache_key)
        if not self._is_redis_active:
            self.fallback_cache.put(full_key, observations)
            return

        try:
            self.fallback_cache.put(full_key, observations)
        except Exception as exc:
            logger.warning(
                "Redis cache write failed: %s. Writing to local LRU cache.", exc
            )
            self.fallback_cache.put(full_key, observations)

    def set(
        self,
        cache_key: str,
        observations: list[ThreatIntelObservation],
        tenant_id: str | None = None,
        ttl_seconds: float | None = None,
    ) -> None:
        """Alias for put method."""
        self.put(cache_key, observations, tenant_id=tenant_id, ttl_seconds=ttl_seconds)
