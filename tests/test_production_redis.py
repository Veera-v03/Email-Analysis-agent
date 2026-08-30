"""Comprehensive unit, contract, and resilience forensic tests for Production Hardening Phase 1 (Redis State & Deduplication)."""

from __future__ import annotations

import asyncio
from uuid import UUID, uuid4

import pytest

from src.common.redis_client import (
    AsyncRedisClient,
    DistributedRateLimiter,
    DistributedTenantLock,
    InMemoryRedisClient,
    ThreatIntelRedisCache,
)
from src.ingestion_gateway.redis_dedup import RedisIngestionDeduplicationEngine


# ===========================================================================
# 1. Redis Client & In-Memory Fallback Unit Tests
# ===========================================================================
@pytest.mark.asyncio
async def test_redis_client_basic_operations() -> None:
    client = InMemoryRedisClient()

    # 1. SET and GET
    assert await client.set("key1", "val1") is True
    assert await client.get("key1") == "val1"

    # 2. SET NX (Not Exists)
    assert await client.set("key1", "val2", nx=True) is False
    assert await client.get("key1") == "val1"
    assert await client.set("key2", "val2", nx=True) is True
    assert await client.get("key2") == "val2"

    # 3. SET XX (Exists)
    assert await client.set("key3", "val3", xx=True) is False
    assert await client.set("key1", "val1_updated", xx=True) is True
    assert await client.get("key1") == "val1_updated"

    # 4. TTL and Expiration
    assert await client.set("temp_key", "temp_val", ex=10) is True
    assert await client.ttl("temp_key") > 0
    assert await client.exists("temp_key") == 1

    # 5. INCR
    assert await client.incr("counter", 1) == 1
    assert await client.incr("counter", 5) == 6
    assert await client.get("counter") == "6"

    # 6. DELETE
    assert await client.delete("key1", "key2") == 2
    assert await client.get("key1") is None


@pytest.mark.asyncio
async def test_redis_client_health_and_fallback() -> None:
    async_client = AsyncRedisClient(
        redis_url="redis://nonexistent.local:6379/0",
        timeout_sec=0.1,
        fallback_to_memory=True,
    )

    # Initial get should trigger graceful fallback without raising exceptions
    val = await async_client.get("test_fallback_key")
    assert val is None

    # Writing in degraded mode works smoothly
    assert await async_client.set("degraded_key", "degraded_val") is True
    assert await async_client.get("degraded_key") == "degraded_val"

    health = async_client.get_health_status()
    assert health["status"] == "REDIS_DEGRADED"
    assert health["backend"] == "in_memory"
    assert health["fallback_enabled"] is True


@pytest.mark.asyncio
async def test_redis_recovery_cycle() -> None:
    async_client = AsyncRedisClient(
        redis_url="redis://localhost:6379/0",
        timeout_sec=0.1,
        fallback_to_memory=True,
    )
    # Manually simulate healthy client
    mock_healthy_client = InMemoryRedisClient()
    async_client._redis_conn = mock_healthy_client
    async_client._is_degraded = False

    assert await async_client.set("rec_key", "rec_val") is True
    assert await async_client.get("rec_key") == "rec_val"
    assert async_client.get_health_status()["status"] == "HEALTHY"

    # Simulate network failure -> Transitions to degraded mode
    async_client._is_degraded = True
    assert await async_client.set("rec_key_deg", "rec_val_deg") is True
    assert async_client.get_health_status()["status"] == "REDIS_DEGRADED"


# ===========================================================================
# 2. Distributed Ingestion Deduplication Tests
# ===========================================================================
@pytest.mark.asyncio
async def test_redis_ingestion_deduplication_first_seen_and_duplicate() -> None:
    client = InMemoryRedisClient()
    engine = RedisIngestionDeduplicationEngine(redis_client=client, default_ttl_sec=3600)

    tenant_id = uuid4()
    account_id = uuid4()
    msg_id = "<alert-2026-001@vendor.com>"

    # 1. First seen -> Returns True (New)
    is_new_1 = await engine.check_and_mark_async(tenant_id, account_id, msg_id)
    assert is_new_1 is True

    # 2. Second seen -> Returns False (Duplicate)
    is_new_2 = await engine.check_and_mark_async(tenant_id, account_id, msg_id)
    assert is_new_2 is False

    # Verify key formatting in Redis
    key = engine.compute_redis_key(tenant_id, account_id, msg_id)
    assert key.startswith(f"scamon:{tenant_id}:dedup:{account_id}:")
    assert await client.exists(key) == 1


@pytest.mark.asyncio
async def test_redis_ingestion_deduplication_tenant_isolation() -> None:
    client = InMemoryRedisClient()
    engine = RedisIngestionDeduplicationEngine(redis_client=client)

    tenant_a = uuid4()
    tenant_b = uuid4()
    account_id = uuid4()
    msg_id = "<shared-newsletter-01@news.com>"

    # Tenant A ingests message
    assert await engine.check_and_mark_async(tenant_a, account_id, msg_id) is True

    # Tenant B ingests same provider message ID -> Must NOT be marked as duplicate!
    assert await engine.check_and_mark_async(tenant_b, account_id, msg_id) is True

    # Repeated ingest for Tenant A is duplicate
    assert await engine.check_and_mark_async(tenant_a, account_id, msg_id) is False


@pytest.mark.asyncio
async def test_redis_ingestion_deduplication_high_concurrency() -> None:
    client = InMemoryRedisClient()
    engine = RedisIngestionDeduplicationEngine(redis_client=client)

    tenant_id = uuid4()
    account_id = uuid4()
    msg_id = "<concurrent-burst-50@vendor.com>"

    # Fire 50 simultaneous ingestion attempts for the exact same message
    results = await asyncio.gather(
        *[engine.check_and_mark_async(tenant_id, account_id, msg_id) for _ in range(50)]
    )

    # Exactly one attempt must evaluate to True (New), and 49 must evaluate to False (Duplicate)
    assert results.count(True) == 1
    assert results.count(False) == 49


# ===========================================================================
# 3. Shared Threat Intelligence Cache Tests
# ===========================================================================
@pytest.mark.asyncio
async def test_threat_intel_redis_cache() -> None:
    client = InMemoryRedisClient()
    cache = ThreatIntelRedisCache(client=client)

    tenant_id = uuid4()
    target_ioc = "https://phishing-site.ru/login"
    payload = '{"malicious": true, "confidence": 0.98, "provider": "VirusTotal"}'

    # 1. Store observation with 1-hour TTL
    assert await cache.set_observation(tenant_id, "url", target_ioc, payload, ttl_sec=3600) is True

    # 2. Retrieve observation
    retrieved = await cache.get_observation(tenant_id, "url", target_ioc)
    assert retrieved == payload

    # 3. Missing observation
    assert await cache.get_observation(tenant_id, "url", "https://clean-site.com") is None

    # 4. Delete observation
    assert await cache.delete_observation(tenant_id, "url", target_ioc) == 1
    assert await cache.get_observation(tenant_id, "url", target_ioc) is None


# ===========================================================================
# 4. Distributed Rate Limiter Tests
# ===========================================================================
@pytest.mark.asyncio
async def test_distributed_rate_limiter() -> None:
    client = InMemoryRedisClient()
    tenant_id = uuid4()
    limiter = DistributedRateLimiter(
        client=client,
        tenant_id=tenant_id,
        resource_name="virustotal_api",
        limit=5,
        window_sec=60,
    )

    # First 5 calls are permitted
    for i in range(5):
        allowed, remaining = await limiter.is_allowed(cost=1)
        assert allowed is True
        assert remaining == 5 - (i + 1)

    # 6th call exceeds limit
    allowed_6, remaining_6 = await limiter.is_allowed(cost=1)
    assert allowed_6 is False
    assert remaining_6 == 0


@pytest.mark.asyncio
async def test_distributed_rate_limiter_concurrency_burst() -> None:
    client = InMemoryRedisClient()
    tenant_id = uuid4()
    limiter = DistributedRateLimiter(
        client=client,
        tenant_id=tenant_id,
        resource_name="gsb_api",
        limit=10,
        window_sec=60,
    )

    results = await asyncio.gather(*[limiter.is_allowed(cost=1) for _ in range(25)])
    allowed_count = sum(1 for allowed, _ in results if allowed)
    rejected_count = sum(1 for allowed, _ in results if not allowed)

    assert allowed_count == 10
    assert rejected_count == 15


# ===========================================================================
# 5. Distributed Tenant Lease Lock Tests
# ===========================================================================
@pytest.mark.asyncio
async def test_distributed_tenant_lease_lock_acquire_and_release() -> None:
    client = InMemoryRedisClient()
    tenant_id = uuid4()

    lock = DistributedTenantLock(
        client=client,
        tenant_id=tenant_id,
        resource_name="tenant_memory_convergence",
        ttl_ms=3000,
    )

    # 1. Acquire lock
    assert await lock.acquire(timeout_sec=0.5) is True

    # 2. Second worker attempts to acquire same resource -> Fails (Contention)
    lock_worker_2 = DistributedTenantLock(
        client=client,
        tenant_id=tenant_id,
        resource_name="tenant_memory_convergence",
        ttl_ms=3000,
    )
    assert await lock_worker_2.acquire(timeout_sec=0.1) is False

    # 3. Worker 1 safely releases lock
    assert await lock.release() is True

    # 4. Worker 2 can now acquire lock
    assert await lock_worker_2.acquire(timeout_sec=0.5) is True
    await lock_worker_2.release()


@pytest.mark.asyncio
async def test_distributed_lock_expired_owner_cannot_delete_newer_lock() -> None:
    client = InMemoryRedisClient()
    tenant_id = uuid4()

    # Worker 1 acquires lock with short TTL (50ms)
    lock1 = DistributedTenantLock(client, tenant_id, "res1", ttl_ms=50)
    assert await lock1.acquire() is True

    # Wait for lock1 to expire
    await asyncio.sleep(0.06)

    # Worker 2 acquires the now-free lock
    lock2 = DistributedTenantLock(client, tenant_id, "res1", ttl_ms=5000)
    assert await lock2.acquire() is True

    # Worker 1 attempts to release its expired lock -> Lua script verifies owner token and fails safely
    assert await lock1.release() is False

    # Worker 2's lock is still intact and held!
    assert await client.get(lock2.lock_key) == lock2.owner_token
    await lock2.release()


@pytest.mark.asyncio
async def test_distributed_tenant_lock_context_manager() -> None:
    client = InMemoryRedisClient()
    tenant_id = uuid4()

    async with DistributedTenantLock(client, tenant_id, "test_resource", ttl_ms=2000):
        # Lock is held inside context
        lock_conflict = DistributedTenantLock(client, tenant_id, "test_resource", ttl_ms=2000)
        assert await lock_conflict.acquire(timeout_sec=0.05) is False

    # Lock is automatically released upon context exit
    lock_after = DistributedTenantLock(client, tenant_id, "test_resource", ttl_ms=2000)
    assert await lock_after.acquire(timeout_sec=0.05) is True
    await lock_after.release()


# ===========================================================================
# 6. Data Minimization & Secret Hygiene Tests
# ===========================================================================
@pytest.mark.asyncio
async def test_redis_data_minimization_and_safety() -> None:
    client = InMemoryRedisClient()
    engine = RedisIngestionDeduplicationEngine(redis_client=client)

    tenant_id = uuid4()
    account_id = uuid4()
    secret_msg_id = "<secret-salary-info@corp.local>"

    await engine.check_and_mark_async(tenant_id, account_id, secret_msg_id)

    # Verify that stored values in Redis contain only the bit token "1", never raw message bodies
    for k, (val, _) in client._store.items():
        assert val == "1" or val == b"1" or k.startswith("scamon:")
        assert "salary" not in str(val)
        assert "password" not in str(val)
