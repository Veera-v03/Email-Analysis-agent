"""Targeted unit, contract, fallback, caching, and tenant isolation tests for Production Hardening Phase 4.2 (Dense Embeddings)."""

from __future__ import annotations

import math
from unittest.mock import MagicMock

import httpx

from src.common.redis_client import InMemoryRedisClient
from src.memory.embeddings.dense_embedding import DenseEmbeddingProvider
from src.memory.embeddings.embedding_provider import (
    DeterministicEmbeddingProvider,
    IEmbeddingProvider,
)
from src.memory.storage.pgvector_store import PgVectorStore


# ===========================================================================
# 1. Contract & Compatibility Tests
# ===========================================================================
def test_dense_embedding_provider_implements_iembedding_provider() -> None:
    provider = DenseEmbeddingProvider(dimension=768)
    assert isinstance(provider, IEmbeddingProvider)
    assert provider.dimension == 768
    assert provider.model_name == "text-embedding-004"
    # Unconfigured API key defaults to degraded state
    assert provider.is_degraded is True
    health = provider.get_health_status()
    assert health["status"] == "DENSE_DEGRADED"
    assert health["fallback_enabled"] is True


def test_empty_text_returns_zero_vector() -> None:
    provider = DenseEmbeddingProvider(dimension=768)
    vec = provider.embed_text("   ")
    assert len(vec) == 768
    assert all(v == 0.0 for v in vec)


# ===========================================================================
# 2. Live Mocked Neural Embedding Tests
# ===========================================================================
def test_dense_embedding_mock_success_and_l2_normalization() -> None:
    mock_raw_vector = [1.0] * 768  # Sum of squares = 768, L2 norm = sqrt(768) ~ 27.7128
    mock_resp = httpx.Response(
        status_code=200,
        json={"embedding": {"values": mock_raw_vector}},
        request=httpx.Request("POST", "https://generativelanguage.googleapis.com/v1beta/models/text-embedding-004:embedContent"),
    )
    mock_client = MagicMock(spec=httpx.Client)
    mock_client.post.return_value = mock_resp

    provider = DenseEmbeddingProvider(
        model="text-embedding-004",
        dimension=768,
        api_key="mock_gemini_api_key",
        http_client=mock_client,
    )
    assert provider.is_degraded is False
    assert provider.get_health_status()["status"] == "DENSE_CONNECTED"

    vec = provider.embed_text("Urgent Wire Transfer Phishing Email")
    assert len(vec) == 768
    # L2 norm must be approximately 1.0
    l2_norm = math.sqrt(sum(v * v for v in vec))
    assert abs(l2_norm - 1.0) < 1e-4
    assert mock_client.post.call_count == 1


def test_dimension_mismatch_triggers_safe_fallback() -> None:
    # API returns 384 dimensions when 768 was expected
    mock_resp = httpx.Response(
        status_code=200,
        json={"embedding": {"values": [0.5] * 384}},
        request=httpx.Request("POST", "https://generativelanguage.googleapis.com/v1beta/models/text-embedding-004:embedContent"),
    )
    mock_client = MagicMock(spec=httpx.Client)
    mock_client.post.return_value = mock_resp

    provider = DenseEmbeddingProvider(
        dimension=768,
        api_key="mock_key",
        http_client=mock_client,
    )

    # Must fall back to deterministic provider with 768 dimensions rather than returning malformed 384 vector
    vec = provider.embed_text("Malicious Domain Alert")
    assert len(vec) == 768


# ===========================================================================
# 3. Tenant-Isolated Redis Caching Tests
# ===========================================================================
def test_tenant_isolated_redis_caching() -> None:
    mock_raw_vector = [0.1] * 768
    mock_resp = httpx.Response(
        status_code=200,
        json={"embedding": {"values": mock_raw_vector}},
        request=httpx.Request("POST", "https://generativelanguage.googleapis.com/v1beta/models/text-embedding-004:embedContent"),
    )
    mock_client = MagicMock(spec=httpx.Client)
    mock_client.post.return_value = mock_resp

    redis_client = InMemoryRedisClient()

    provider = DenseEmbeddingProvider(
        dimension=768,
        api_key="mock_key",
        redis_client=redis_client,
        http_client=mock_client,
    )

    test_text = "Credential Harvesting Attack Scenario"

    # 1. Tenant Alpha embeds text -> HTTP call issued
    vec_alpha = provider.embed_text(test_text, tenant_id="tenant_alpha")
    assert len(vec_alpha) == 768
    assert mock_client.post.call_count == 1

    # 2. Tenant Alpha embeds identical text again -> Cached (0 new HTTP calls)
    vec_alpha_cached = provider.embed_text(test_text, tenant_id="tenant_alpha")
    assert vec_alpha_cached == vec_alpha
    assert mock_client.post.call_count == 1

    # 3. Tenant Bravo embeds identical text -> Must make separate HTTP call due to tenant namespace isolation!
    vec_bravo = provider.embed_text(test_text, tenant_id="tenant_bravo")
    assert len(vec_bravo) == 768
    assert mock_client.post.call_count == 2


# ===========================================================================
# 4. Resilience & Fallback Tests
# ===========================================================================
def test_provider_network_error_falls_back_gracefully() -> None:
    mock_client = MagicMock(spec=httpx.Client)
    mock_client.post.side_effect = httpx.ConnectTimeout("Connection timed out to Google API")

    provider = DenseEmbeddingProvider(
        dimension=768,
        api_key="mock_key",
        http_client=mock_client,
    )

    # Must NOT crash; should return deterministic fallback vector and mark state as degraded
    vec = provider.embed_text("Suspicious attachment detected")
    assert len(vec) == 768
    assert provider.is_degraded is True
    assert provider.get_health_status()["status"] == "DENSE_DEGRADED"


def test_rate_limiter_suppression_routes_to_fallback() -> None:
    redis_client = InMemoryRedisClient()

    mock_resp = httpx.Response(
        status_code=200,
        json={"embedding": {"values": [0.2] * 768}},
        request=httpx.Request("POST", "https://generativelanguage.googleapis.com/v1beta/models/text-embedding-004:embedContent"),
    )
    mock_client = MagicMock(spec=httpx.Client)
    mock_client.post.return_value = mock_resp

    # Rate limit = 1 per minute
    provider = DenseEmbeddingProvider(
        dimension=768,
        api_key="mock_key",
        redis_client=redis_client,
        rate_limit_per_min=1,
        http_client=mock_client,
    )

    # Call 1: Within limit -> Uses mock HTTP
    vec_1 = provider.embed_text("First threat query", tenant_id="tenant_x")
    assert len(vec_1) == 768
    assert mock_client.post.call_count == 1

    # Call 2: Rate limit exceeded -> Falls back to deterministic (0 new HTTP calls)
    vec_2 = provider.embed_text("Second threat query", tenant_id="tenant_x")
    assert len(vec_2) == 768
    assert mock_client.post.call_count == 1


# ===========================================================================
# 5. Batch Embedding Tests
# ===========================================================================
def test_batch_embedding_deduplication_and_order_preservation() -> None:
    mock_resp = httpx.Response(
        status_code=200,
        json={"embedding": {"values": [0.3] * 768}},
        request=httpx.Request("POST", "https://generativelanguage.googleapis.com/v1beta/models/text-embedding-004:embedContent"),
    )
    mock_client = MagicMock(spec=httpx.Client)
    mock_client.post.return_value = mock_resp

    provider = DenseEmbeddingProvider(
        dimension=768,
        api_key="mock_key",
        http_client=mock_client,
    )

    batch_input = [
        "Item Alpha",
        "Item Beta",
        "Item Alpha",  # Duplicate
        "Item Gamma",
    ]

    results = provider.embed_batch(batch_input)
    assert len(results) == 4
    # Duplicate item 0 and item 2 must have identical vectors
    assert results[0] == results[2]
    # Deduplication resulted in only 3 distinct network calls
    assert mock_client.post.call_count == 3


def test_pgvector_store_dense_dimension_compatibility() -> None:
    dense_provider = DenseEmbeddingProvider(dimension=768)
    vec = dense_provider.embed_text("Phishing campaign match")

    pg_store = PgVectorStore(dimension=768)
    assert pg_store.dimension == 768

    # Query with 768 dimension vector in PgVectorStore
    results = pg_store.similarity_search(query_vector=vec, top_k=3)
    assert isinstance(results, list)


def test_backward_compatibility_with_deterministic_provider() -> None:
    det_provider = DeterministicEmbeddingProvider(dimension=64)
    assert isinstance(det_provider, IEmbeddingProvider)
    vec = det_provider.embed_text("Test query")
    assert len(vec) == 64
