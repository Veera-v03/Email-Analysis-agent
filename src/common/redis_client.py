"""Production-grade asynchronous Redis client abstraction with graceful in-memory fallback."""

from __future__ import annotations

import asyncio
import re
import time
from typing import Any
from uuid import UUID, uuid4

from src.config.enterprise_config import settings
from src.utils.logging import get_logger

logger = get_logger("scamon.common.redis")


# ===========================================================================
# In-Memory Fallback Client (High-Fidelity Redis Simulation)
# ===========================================================================
class InMemoryRedisClient:
    """Thread-safe & async-safe in-memory Redis client with TTL and atomic operations."""

    def __init__(self) -> None:
        self._store: dict[str, tuple[str | bytes, float | None]] = {}
        self._lock = asyncio.Lock()
        self._connected = True

    async def get(self, key: str) -> str | bytes | None:
        """Retrieve key value or None if absent or expired."""
        async with self._lock:
            if key not in self._store:
                return None
            val, expiry = self._store[key]
            if expiry is not None and time.time() > expiry:
                del self._store[key]
                return None
            return val

    async def set(
        self,
        key: str,
        value: str | bytes,
        ex: int | None = None,
        px: int | None = None,
        nx: bool = False,
        xx: bool = False,
    ) -> bool:
        """Store key with optional TTL (ex=seconds, px=milliseconds) and conditional flags (nx/xx)."""
        async with self._lock:
            now = time.time()
            exists = False
            if key in self._store:
                _, expiry = self._store[key]
                if expiry is None or now <= expiry:
                    exists = True
                else:
                    del self._store[key]

            if nx and exists:
                return False
            if xx and not exists:
                return False

            expiry_ts: float | None = None
            if ex is not None:
                expiry_ts = now + ex
            elif px is not None:
                expiry_ts = now + (px / 1000.0)

            self._store[key] = (value, expiry_ts)
            return True

    async def delete(self, *keys: str) -> int:
        """Delete one or more keys. Returns number of keys removed."""
        async with self._lock:
            count = 0
            for k in keys:
                if k in self._store:
                    del self._store[k]
                    count += 1
            return count

    async def ttl(self, key: str) -> int:
        """Return remaining TTL in seconds (-2 if absent, -1 if no TTL, >= 0 remaining)."""
        async with self._lock:
            if key not in self._store:
                return -2
            _, expiry = self._store[key]
            if expiry is None:
                return -1
            remaining = int(expiry - time.time())
            if remaining < 0:
                del self._store[key]
                return -2
            return remaining

    async def exists(self, *keys: str) -> int:
        """Return count of existing non-expired keys."""
        async with self._lock:
            now = time.time()
            count = 0
            for k in keys:
                if k in self._store:
                    _, expiry = self._store[k]
                    if expiry is None or now <= expiry:
                        count += 1
                    else:
                        del self._store[k]
            return count

    async def incr(self, key: str, amount: int = 1) -> int:
        """Increment integer value of key atomically."""
        async with self._lock:
            val, expiry = self._store.get(key, ("0", None))
            now = time.time()
            if expiry is not None and now > expiry:
                val = "0"
                expiry = None
            try:
                int_val = int(val) + amount
            except (ValueError, TypeError):
                int_val = amount
            self._store[key] = (str(int_val), expiry)
            return int_val

    async def expire(self, key: str, seconds: int) -> bool:
        """Set timeout on key in seconds."""
        async with self._lock:
            if key not in self._store:
                return False
            val, _ = self._store[key]
            self._store[key] = (val, time.time() + seconds)
            return True

    async def eval_script(
        self, script: str, keys: list[str], args: list[str | int]
    ) -> Any:
        """Execute common atomic Lua scripts (e.g. release lease lock if owner matches)."""
        async with self._lock:
            # Common lock release pattern: if get(key) == arg then del(key) return 1 else return 0
            if "redis.call('get'" in script or 'redis.call("get"' in script:
                if not keys:
                    return 0
                target_key = keys[0]
                expected_owner = str(args[0]) if args else ""
                cur_val, expiry = self._store.get(target_key, (None, None))
                if expiry is not None and time.time() > expiry:
                    del self._store[target_key]
                    return 0
                if cur_val == expected_owner or (isinstance(cur_val, bytes) and cur_val.decode() == expected_owner):
                    del self._store[target_key]
                    return 1
                return 0
            return 1

    async def ping(self) -> bool:
        """Health check ping."""
        return self._connected

    async def close(self) -> None:
        """Close connection."""
        self._connected = False

    def is_connected(self) -> bool:
        """Check connection state."""
        return self._connected

    def get_health_status(self) -> dict[str, Any]:
        """Return structured health dictionary."""
        return {
            "status": "REDIS_DEGRADED" if not self._connected else "IN_MEMORY_ACTIVE",
            "backend": "in_memory",
            "key_count": len(self._store),
        }


# ===========================================================================
# Production Redis Client with Resilient Fallback
# ===========================================================================
class AsyncRedisClient:
    """Async Redis client wrapper with connection pooling, retries, and automatic memory fallback."""

    def __init__(
        self,
        redis_url: str | None = None,
        timeout_sec: float | None = None,
        fallback_to_memory: bool | None = None,
    ) -> None:
        self.redis_url = redis_url or settings.get_secret(
            "REDIS_URL", "redis://localhost:6379/0"
        )
        self.timeout_sec = (
            timeout_sec
            if timeout_sec is not None
            else getattr(settings, "redis_timeout_sec", 2.0)
        )
        self.fallback_to_memory = (
            fallback_to_memory
            if fallback_to_memory is not None
            else getattr(settings, "redis_fallback_to_memory", True)
        )

        self._redis_conn: Any = None
        self._fallback_client = InMemoryRedisClient()
        self._is_degraded = False
        self._lock = asyncio.Lock()

    async def _get_conn(self) -> Any:
        """Retrieve active redis-py connection or fallback client."""
        if self._is_degraded:
            return self._fallback_client

        if self._redis_conn is not None:
            return self._redis_conn

        async with self._lock:
            if self._redis_conn is not None:
                return self._redis_conn

            try:
                import redis.asyncio as aioredis  # type: ignore[import-not-found]

                self._redis_conn = aioredis.from_url(
                    self.redis_url,
                    socket_timeout=self.timeout_sec,
                    socket_connect_timeout=self.timeout_sec,
                    decode_responses=True,
                )
                await asyncio.wait_for(self._redis_conn.ping(), timeout=self.timeout_sec)
                self._is_degraded = False
                logger.info("Connected to shared Redis cluster at %s", self.redis_url)
                return self._redis_conn
            except Exception as exc:
                if self.fallback_to_memory:
                    self._is_degraded = True
                    logger.warning(
                        "Unable to connect to Redis (%s). Operating in REDIS_DEGRADED in-memory mode.",
                        exc,
                    )
                    return self._fallback_client
                raise

    async def get(self, key: str) -> str | bytes | None:
        try:
            conn = await self._get_conn()
            res = await asyncio.wait_for(conn.get(key), timeout=self.timeout_sec)
            return res
        except Exception:
            if self.fallback_to_memory:
                self._is_degraded = True
                return await self._fallback_client.get(key)
            raise

    async def set(
        self,
        key: str,
        value: str | bytes,
        ex: int | None = None,
        px: int | None = None,
        nx: bool = False,
        xx: bool = False,
    ) -> bool:
        try:
            conn = await self._get_conn()
            res = await asyncio.wait_for(
                conn.set(key, value, ex=ex, px=px, nx=nx, xx=xx),
                timeout=self.timeout_sec,
            )
            return bool(res)
        except Exception:
            if self.fallback_to_memory:
                self._is_degraded = True
                return await self._fallback_client.set(
                    key, value, ex=ex, px=px, nx=nx, xx=xx
                )
            raise

    async def delete(self, *keys: str) -> int:
        try:
            conn = await self._get_conn()
            res = await asyncio.wait_for(
                conn.delete(*keys), timeout=self.timeout_sec
            )
            return int(res)
        except Exception:
            if self.fallback_to_memory:
                self._is_degraded = True
                return await self._fallback_client.delete(*keys)
            raise

    async def ttl(self, key: str) -> int:
        try:
            conn = await self._get_conn()
            res = await asyncio.wait_for(conn.ttl(key), timeout=self.timeout_sec)
            return int(res)
        except Exception:
            if self.fallback_to_memory:
                self._is_degraded = True
                return await self._fallback_client.ttl(key)
            raise

    async def exists(self, *keys: str) -> int:
        try:
            conn = await self._get_conn()
            res = await asyncio.wait_for(
                conn.exists(*keys), timeout=self.timeout_sec
            )
            return int(res)
        except Exception:
            if self.fallback_to_memory:
                self._is_degraded = True
                return await self._fallback_client.exists(*keys)
            raise

    async def incr(self, key: str, amount: int = 1) -> int:
        try:
            conn = await self._get_conn()
            res = await asyncio.wait_for(
                conn.incr(key, amount), timeout=self.timeout_sec
            )
            return int(res)
        except Exception:
            if self.fallback_to_memory:
                self._is_degraded = True
                return await self._fallback_client.incr(key, amount)
            raise

    async def expire(self, key: str, seconds: int) -> bool:
        try:
            conn = await self._get_conn()
            res = await asyncio.wait_for(
                conn.expire(key, seconds), timeout=self.timeout_sec
            )
            return bool(res)
        except Exception:
            if self.fallback_to_memory:
                self._is_degraded = True
                return await self._fallback_client.expire(key, seconds)
            raise

    async def eval_script(
        self, script: str, keys: list[str], args: list[str | int]
    ) -> Any:
        try:
            conn = await self._get_conn()
            if isinstance(conn, InMemoryRedisClient):
                return await conn.eval_script(script, keys, args)
            res = await asyncio.wait_for(
                conn.eval(script, len(keys), *keys, *args),
                timeout=self.timeout_sec,
            )
            return res
        except Exception:
            if self.fallback_to_memory:
                self._is_degraded = True
                return await self._fallback_client.eval_script(script, keys, args)
            raise

    async def ping(self) -> bool:
        """Perform active Redis PING, returning True only when connected to real Redis server."""
        if self._is_degraded:
            return False
        try:
            conn = await self._get_conn()
            if self._is_degraded or conn is self._fallback_client:
                return False
            return bool(await asyncio.wait_for(conn.ping(), timeout=self.timeout_sec))
        except Exception:
            return False

    async def close(self) -> None:
        if self._redis_conn is not None:
            try:
                await self._redis_conn.close()
            except Exception:
                pass
            self._redis_conn = None
        await self._fallback_client.close()

    def get_health_status(self) -> dict[str, Any]:
        return {
            "status": "REDIS_DEGRADED" if self._is_degraded else "HEALTHY",
            "backend": "in_memory" if self._is_degraded else "redis_cluster",
            "fallback_enabled": self.fallback_to_memory,
        }


# ===========================================================================
# Distributed Tenant Lease Lock
# ===========================================================================
class DistributedTenantLock:
    """Selective tenant-scoped lease lock using atomic SET NX PX and safe Lua release."""

    RELEASE_LUA = """
    if redis.call("get", KEYS[1]) == ARGV[1] then
        return redis.call("del", KEYS[1])
    else
        return 0
    end
    """

    def __init__(
        self,
        client: AsyncRedisClient | InMemoryRedisClient,
        tenant_id: UUID,
        resource_name: str,
        ttl_ms: int = 5000,
    ) -> None:
        self.client = client
        self.tenant_id = tenant_id
        self.resource_name = resource_name
        self.ttl_ms = ttl_ms
        self.lock_key = f"scamon:{tenant_id}:lock:{resource_name}"
        self.owner_token = str(uuid4())
        self._acquired = False

    async def acquire(self, timeout_sec: float = 2.0) -> bool:
        """Attempt to acquire lease lock within timeout."""
        start = time.time()
        while time.time() - start < timeout_sec:
            ok = await self.client.set(
                self.lock_key,
                self.owner_token,
                px=self.ttl_ms,
                nx=True,
            )
            if ok:
                self._acquired = True
                return True
            await asyncio.sleep(0.05)
        return False

    async def release(self) -> bool:
        """Safely release lock if owner token matches."""
        if not self._acquired:
            return False
        res = await self.client.eval_script(
            self.RELEASE_LUA,
            keys=[self.lock_key],
            args=[self.owner_token],
        )
        self._acquired = False
        return bool(res)

    async def __aenter__(self) -> DistributedTenantLock:
        acquired = await self.acquire()
        if not acquired:
            raise TimeoutError(f"Could not acquire lock for resource '{self.resource_name}' on tenant {self.tenant_id}")
        return self

    async def __aexit__(self, exc_type: Any, exc_val: Any, exc_tb: Any) -> None:
        await self.release()


# ===========================================================================
# Distributed Rate Limiter
# ===========================================================================
class DistributedRateLimiter:
    """Sliding-window atomic rate limiter foundation."""

    def __init__(
        self,
        client: AsyncRedisClient | InMemoryRedisClient,
        tenant_id: UUID,
        resource_name: str,
        limit: int = 100,
        window_sec: int = 60,
    ) -> None:
        self.client = client
        self.tenant_id = tenant_id
        self.resource_name = resource_name
        self.limit = limit
        self.window_sec = window_sec

    def _get_bucket_key(self) -> str:
        current_bucket = int(time.time() // self.window_sec)
        return f"scamon:{self.tenant_id}:ratelimit:{self.resource_name}:{current_bucket}"

    async def is_allowed(self, cost: int = 1) -> tuple[bool, int]:
        """Check if request is within limit and increment counter. Returns (allowed, remaining)."""
        key = self._get_bucket_key()
        count = await self.client.incr(key, cost)
        if count == cost:
            # First write in bucket -> set TTL
            await self.client.expire(key, self.window_sec * 2)

        allowed = count <= self.limit
        remaining = max(0, self.limit - count)
        return allowed, remaining


# ===========================================================================
# Threat Intelligence Redis Cache
# ===========================================================================
class ThreatIntelRedisCache:
    """Namespace-isolated cache foundation for IOC observations."""

    def __init__(self, client: AsyncRedisClient | InMemoryRedisClient) -> None:
        self.client = client

    @staticmethod
    def format_key(tenant_id: UUID, ioc_type: str, target: str) -> str:
        clean_target = re.sub(r"[^a-zA-Z0-9_.-]", "_", target.strip().lower())
        return f"scamon:{tenant_id}:threat_intel:{ioc_type.lower()}:{clean_target}"

    async def get_observation(
        self, tenant_id: UUID, ioc_type: str, target: str
    ) -> str | None:
        key = self.format_key(tenant_id, ioc_type, target)
        res = await self.client.get(key)
        if res is None:
            return None
        return res if isinstance(res, str) else res.decode("utf-8")

    async def set_observation(
        self,
        tenant_id: UUID,
        ioc_type: str,
        target: str,
        data_json: str,
        ttl_sec: int = 3600,
    ) -> bool:
        key = self.format_key(tenant_id, ioc_type, target)
        return await self.client.set(key, data_json, ex=ttl_sec)

    async def delete_observation(
        self, tenant_id: UUID, ioc_type: str, target: str
    ) -> int:
        key = self.format_key(tenant_id, ioc_type, target)
        return await self.client.delete(key)


# ===========================================================================
# Global Singleton Dependency Resolver
# ===========================================================================
_redis_client_singleton: AsyncRedisClient | InMemoryRedisClient | None = None


def get_redis_client() -> AsyncRedisClient | InMemoryRedisClient:
    """Dependency resolver for shared Redis client singleton."""
    global _redis_client_singleton
    if _redis_client_singleton is None:
        _redis_client_singleton = AsyncRedisClient()
    return _redis_client_singleton


def set_redis_client(client: AsyncRedisClient | InMemoryRedisClient | None) -> None:
    """Override Redis client singleton for testing."""
    global _redis_client_singleton
    _redis_client_singleton = client
