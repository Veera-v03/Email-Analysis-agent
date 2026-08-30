"""Targeted unit, contract, fallback, and tenant isolation tests for Production Hardening Phase 4.1 (pgvector)."""

from __future__ import annotations

import json
from datetime import UTC, datetime
from unittest.mock import MagicMock

import pytest

from src.memory.embeddings.embedding_provider import DeterministicEmbeddingProvider
from src.memory.models.memory_models import (
    BaseMemoryRecord,
    MemoryType,
)
from src.memory.storage.pgvector_store import PgVectorStore
from src.memory.storage.vector_store import InMemoryVectorStore, IVectorStore


# ===========================================================================
# Helper Fixtures
# ===========================================================================
def create_sample_record(
    memory_id: str,
    tenant_id: str = "tenant_alpha",
    vector: tuple[float, ...] = (0.5,) * 64,
    subject: str = "Urgent Wire Transfer Request",
) -> BaseMemoryRecord:
    return BaseMemoryRecord(
        memory_id=memory_id,
        memory_type=MemoryType.INVESTIGATION,
        confidence_score=0.95,
        created_at=datetime.now(UTC).isoformat(),
        vector=vector,
        metadata={
            "tenant_id": tenant_id,
            "subject": subject,
            "verdict": "MALICIOUS",
        },
    )


# ===========================================================================
# 1. Contract & Compatibility Tests
# ===========================================================================
def test_pgvector_store_implements_ivector_store() -> None:
    store = PgVectorStore(dimension=64)
    assert isinstance(store, IVectorStore)
    assert store.dimension == 64
    # Default without configured connection is degraded in-memory fallback
    assert store.is_degraded is True
    health = store.get_health_status()
    assert health["status"] == "PGVECTOR_DEGRADED"
    assert health["fallback_enabled"] is True


def test_dimension_validation_enforced() -> None:
    store = PgVectorStore(dimension=64)
    invalid_vector = (0.1,) * 32  # 32 != 64
    record = create_sample_record("rec_invalid_dim", vector=invalid_vector)

    with pytest.raises(ValueError, match="Vector dimension mismatch"):
        store.insert(record)

    with pytest.raises(ValueError, match="Vector dimension mismatch"):
        store.similarity_search(query_vector=invalid_vector)


# ===========================================================================
# 2. In-Memory Resilient Fallback CRUD & Search Tests
# ===========================================================================
def test_pgvector_fallback_insert_get_update_delete() -> None:
    store = PgVectorStore(dimension=64)
    vec = (0.1,) * 64
    record = create_sample_record("rec_crud_1", vector=vec)

    # 1. Insert & Count
    store.insert(record)
    assert store.count() == 1

    # 2. Get
    fetched = store.get("rec_crud_1")
    assert fetched is not None
    assert fetched.memory_id == "rec_crud_1"
    assert fetched.metadata["subject"] == "Urgent Wire Transfer Request"

    # 3. Update
    updated_rec = create_sample_record("rec_crud_1", vector=vec, subject="Updated Wire Transfer")
    store.update(updated_rec)
    fetched_after = store.get("rec_crud_1")
    assert fetched_after is not None
    assert fetched_after.metadata["subject"] == "Updated Wire Transfer"

    # 4. Delete
    deleted = store.delete("rec_crud_1")
    assert deleted is True
    assert store.count() == 0
    assert store.get("rec_crud_1") is None


def test_pgvector_fallback_cosine_similarity_search() -> None:
    embedder = DeterministicEmbeddingProvider(dimension=64)
    store = PgVectorStore(dimension=64)

    # Insert 2 distinct threat records
    vec_phish = embedder.embed_text("Urgent Wire Transfer Immediate Payment")
    rec_phish = create_sample_record("rec_phish", vector=vec_phish, subject="Urgent Wire Transfer Immediate Payment")
    store.insert(rec_phish)

    vec_clean = embedder.embed_text("Weekly team lunch reminder")
    rec_clean = create_sample_record("rec_clean", vector=vec_clean, subject="Weekly team lunch reminder")
    store.insert(rec_clean)

    # Search with a query similar to the wire transfer
    query_vec = embedder.embed_text("Urgent wire payment")
    results = store.similarity_search(query_vector=query_vec, top_k=2)

    assert len(results) == 2
    # The phishing record must be ranked first with higher similarity score
    assert results[0].record.memory_id == "rec_phish"
    assert results[0].similarity_score > results[1].similarity_score


# ===========================================================================
# 3. Strict Tenant Isolation Tests
# ===========================================================================
def test_strict_tenant_isolation_at_query_boundary() -> None:
    embedder = DeterministicEmbeddingProvider(dimension=64)
    store = PgVectorStore(dimension=64)

    vec = embedder.embed_text("Malicious Credential Harvesting Phishing Email")

    # Insert identical vector for Tenant A and Tenant B
    rec_tenant_a = create_sample_record("rec_a", tenant_id="tenant_alpha", vector=vec)
    rec_tenant_b = create_sample_record("rec_b", tenant_id="tenant_bravo", vector=vec)
    store.insert(rec_tenant_a)
    store.insert(rec_tenant_b)

    # Search specifying Tenant Alpha filter
    query_vec = embedder.embed_text("Credential harvesting login page")
    results_a = store.similarity_search(
        query_vector=query_vec,
        metadata_filters={"tenant_id": "tenant_alpha"},
    )

    # Must only return Tenant Alpha's record!
    assert len(results_a) == 1
    assert results_a[0].record.memory_id == "rec_a"
    assert results_a[0].record.metadata["tenant_id"] == "tenant_alpha"

    # Search specifying Tenant Bravo filter
    results_b = store.similarity_search(
        query_vector=query_vec,
        metadata_filters={"tenant_id": "tenant_bravo"},
    )
    assert len(results_b) == 1
    assert results_b[0].record.memory_id == "rec_b"
    assert results_b[0].record.metadata["tenant_id"] == "tenant_bravo"

    # Search specifying Non-Existent Tenant Charlie -> 0 results
    results_c = store.similarity_search(
        query_vector=query_vec,
        metadata_filters={"tenant_id": "tenant_charlie"},
    )
    assert len(results_c) == 0


# ===========================================================================
# 4. Mock SQL Engine / Live Query Execution Path Tests
# ===========================================================================
def test_mock_sql_engine_pgvector_query_construction() -> None:
    mock_conn = MagicMock()
    mock_engine = MagicMock()
    mock_engine.connect.return_value.__enter__.return_value = mock_conn

    # Simulate query results from PostgreSQL pgvector
    mock_row = [
        "rec_mock_1",
        "tenant_alpha",
        "investigation",
        json.dumps({"tenant_id": "tenant_alpha", "confidence_score": 0.95}),
        datetime.now(UTC).isoformat(),
        0.9123,  # similarity_score
    ]
    mock_conn.execute.return_value.fetchall.return_value = [mock_row]

    store = PgVectorStore(dimension=64, db_engine=mock_engine)
    assert store.is_degraded is False
    assert store.get_health_status()["status"] == "PGVECTOR_CONNECTED"

    query_vec = (0.5,) * 64
    results = store.similarity_search(
        query_vector=query_vec,
        top_k=5,
        metadata_filters={"tenant_id": "tenant_alpha"},
    )

    assert len(results) == 1
    assert results[0].record.memory_id == "rec_mock_1"
    assert results[0].similarity_score == 0.9123

    # Verify executed SQL contains pgvector cosine distance operator <=> and WHERE tenant_id
    executed_sql = str(mock_conn.execute.call_args[0][0])
    assert "<=>" in executed_sql
    assert "tenant_id = :tenant_id" in executed_sql
    assert "ORDER BY embedding <=>" in executed_sql


def test_backward_compatibility_with_in_memory_vector_store() -> None:
    legacy_store = InMemoryVectorStore()
    assert isinstance(legacy_store, IVectorStore)
    rec = create_sample_record("rec_legacy")
    legacy_store.insert(rec)
    assert legacy_store.count() == 1
    assert legacy_store.get("rec_legacy") is not None
