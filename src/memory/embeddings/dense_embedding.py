"""Production dense neural embedding provider with Google Gemini backend, Redis caching, and deterministic fallback."""

from __future__ import annotations

import asyncio
import hashlib
import json
import math
from collections.abc import Sequence
from typing import Any
from uuid import UUID, uuid5

import httpx

from src.common.redis_client import (
    AsyncRedisClient,
    DistributedRateLimiter,
    InMemoryRedisClient,
)
from src.config.enterprise_config import settings
from src.config.logging import get_logger
from src.memory.embeddings.embedding_provider import (
    DeterministicEmbeddingProvider,
    IEmbeddingProvider,
)

logger = get_logger("scamon.memory.embeddings.dense")

NAMESPACE_TENANT = UUID("6c41d938-cf1c-49f8-9199-a67d033bb082")


class DenseEmbeddingProvider(IEmbeddingProvider):
    """Production neural embedding provider with tenant-isolated Redis caching, rate limiting, and graceful fallback."""

    def __init__(
        self,
        model: str | None = None,
        dimension: int | None = None,
        api_key: str | None = None,
        timeout_seconds: float | None = None,
        redis_client: AsyncRedisClient | InMemoryRedisClient | None = None,
        rate_limit_per_min: int | None = None,
        fallback_provider: IEmbeddingProvider | None = None,
        http_client: httpx.Client | None = None,
    ) -> None:
        self._model = model or getattr(settings, "embedding_model", "text-embedding-004")
        self._dim = dimension or getattr(settings, "embedding_dimension", 768)
        self._api_key = (
            api_key
            or settings.get_secret("EMBEDDING_API_KEY")
            or settings.get_secret("GEMINI_API_KEY")
        )
        self._timeout_seconds = (
            timeout_seconds
            if timeout_seconds is not None
            else getattr(settings, "embedding_timeout_sec", 5.0)
        )
        self._redis_client = redis_client
        self._rate_limit = (
            rate_limit_per_min
            if rate_limit_per_min is not None
            else getattr(settings, "embedding_rate_limit_per_min", 300)
        )
        self._fallback_provider = fallback_provider or DeterministicEmbeddingProvider(
            dimension=self._dim
        )
        self._http_client = http_client
        self._is_degraded = False

        if not self._api_key:
            self._is_degraded = True
            logger.info(
                "Embedding API key not configured; initialized in degraded deterministic fallback mode"
            )

    @property
    def dimension(self) -> int:
        return self._dim

    @property
    def model_name(self) -> str:
        return self._model

    @property
    def is_degraded(self) -> bool:
        return self._is_degraded

    def get_health_status(self) -> dict[str, Any]:
        """Report provider health and connection state."""
        return {
            "status": "DENSE_DEGRADED" if (self._is_degraded or not self._api_key) else "DENSE_CONNECTED",
            "model": self._model,
            "dimension": self._dim,
            "fallback_enabled": True,
        }

    @staticmethod
    def _normalize_vector(vector: Sequence[float]) -> tuple[float, ...]:
        """L2-normalize a float vector for deterministic cosine similarity distance."""
        l2_norm = math.sqrt(sum(v * v for v in vector))
        if l2_norm > 0:
            return tuple(round(v / l2_norm, 6) for v in vector)
        return tuple(0.0 for _ in vector)

    def _get_cache_key(self, tenant_id: str, text_hash: str) -> str:
        """Construct tenant-scoped content-addressed Redis cache key."""
        return f"scamon:{tenant_id}:embedding:{self._model}:{text_hash}"

    def _to_uuid(self, tenant_id: str) -> UUID:
        try:
            return UUID(tenant_id)
        except ValueError:
            return uuid5(NAMESPACE_TENANT, str(tenant_id))

    def _run_async(self, coro: Any) -> Any:
        """Helper to run async Redis operations synchronously in sync embedding methods."""
        try:
            loop = asyncio.get_running_loop()
        except RuntimeError:
            loop = None

        if loop is not None and loop.is_running():
            import concurrent.futures
            with concurrent.futures.ThreadPoolExecutor(max_workers=1) as pool:
                return pool.submit(asyncio.run, coro).result()
        return asyncio.run(coro)

    def embed_text(
        self,
        text: str,
        tenant_id: str = "default",
    ) -> tuple[float, ...]:
        """Generate normalized dense embedding vector with Redis caching and fallback protection."""
        canon_text = text.strip()
        if not canon_text:
            return (0.0,) * self._dim

        text_hash = hashlib.sha256(canon_text.encode("utf-8")).hexdigest()

        # 1. Check Redis Cache
        if self._redis_client:
            cache_key = self._get_cache_key(tenant_id, text_hash)
            try:
                cached_json = self._run_async(self._redis_client.get(cache_key))
                if cached_json:
                    val_str = cached_json if isinstance(cached_json, str) else cached_json.decode("utf-8")
                    data = json.loads(val_str)
                    vec = tuple(float(v) for v in data["vector"])
                    if len(vec) == self._dim:
                        return vec
            except Exception as exc:
                logger.debug("Redis embedding cache lookup error: %s", exc)

        # 2. If degraded or unconfigured, route to deterministic fallback
        if self._is_degraded or not self._api_key:
            return self._fallback_provider.embed_text(canon_text)

        # 3. Check rate limits
        if self._redis_client:
            tenant_uuid = self._to_uuid(tenant_id)
            limiter = DistributedRateLimiter(
                client=self._redis_client,
                tenant_id=tenant_uuid,
                resource_name="embedding",
                limit=self._rate_limit,
                window_sec=60,
            )
            try:
                allowed, _ = self._run_async(limiter.is_allowed(1))
                if not allowed:
                    logger.warning("Embedding rate limit exceeded for tenant '%s'; using fallback", tenant_id)
                    return self._fallback_provider.embed_text(canon_text)
            except Exception as exc:
                logger.debug("Rate limiter check error: %s", exc)

        # 4. Call Neural Embedding Endpoint
        endpoint = (
            f"https://generativelanguage.googleapis.com/v1beta/models/{self._model}:embedContent"
        )
        params = {"key": self._api_key}
        payload = {
            "content": {
                "parts": [{"text": canon_text}]
            }
        }

        client = self._http_client or httpx.Client(timeout=self._timeout_seconds)
        try:
            resp = client.post(endpoint, params=params, json=payload)
            if resp.status_code != 200:
                logger.warning(
                    "Neural embedding API error HTTP %d; falling back to deterministic",
                    resp.status_code,
                )
                self._is_degraded = True
                return self._fallback_provider.embed_text(canon_text)

            res_json = resp.json()
            raw_values = res_json.get("embedding", {}).get("values", [])
            if not raw_values or len(raw_values) != self._dim:
                logger.warning(
                    "Embedding dimension mismatch: expected %d, got %d; falling back",
                    self._dim,
                    len(raw_values),
                )
                return self._fallback_provider.embed_text(canon_text)

            normalized_vec = self._normalize_vector(raw_values)

            # Store in Redis Cache
            if self._redis_client:
                cache_key = self._get_cache_key(tenant_id, text_hash)
                ttl = getattr(settings, "embedding_cache_ttl_sec", 86400)
                cache_val = json.dumps({"vector": list(normalized_vec)})
                try:
                    self._run_async(self._redis_client.set(cache_key, cache_val, ex=ttl))
                except Exception as exc:
                    logger.debug("Redis cache write error: %s", exc)

            return normalized_vec

        except Exception as exc:
            logger.warning(
                "Neural embedding request failed (%s); falling back to deterministic",
                type(exc).__name__,
            )
            self._is_degraded = True
            return self._fallback_provider.embed_text(canon_text)

        finally:
            if self._http_client is None:
                client.close()

    def embed_batch(
        self,
        texts: Sequence[str],
        tenant_id: str = "default",
    ) -> list[tuple[float, ...]]:
        """Batch embedding with deduplication and input order preservation."""
        if not texts:
            return []

        # Deduplicate texts while preserving indices
        unique_texts: dict[str, tuple[float, ...]] = {}
        for text in texts:
            canon = text.strip()
            if canon not in unique_texts:
                unique_texts[canon] = self.embed_text(canon, tenant_id=tenant_id)

        return [unique_texts[t.strip()] for t in texts]
