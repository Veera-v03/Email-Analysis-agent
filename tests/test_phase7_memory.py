"""Comprehensive unit and integration test suite for Phase 7 Memory & Learning Intelligence."""

from __future__ import annotations

import tempfile
from pathlib import Path

from src.memory import (
    AnalystFeedbackSystem,
    DeterministicEmbeddingProvider,
    InMemoryVectorStore,
    InvestigationMemory,
    InvestigationRepository,
    LearningPipeline,
    MemoryManager,
    MemoryRetrievalService,
    MemoryType,
)
from src.models.agent import AgentState
from src.models.email import EmailAttachment, EmailHeader, EmailInput
from src.models.evidence import Evidence, EvidenceSeverity
from src.planner.explainability import ExplainabilityEngine
from src.planner.reasoning import ReasoningEngine

# --- 1. Embedding Provider Tests ---


def test_deterministic_embedding_provider_properties() -> None:
    embedder = DeterministicEmbeddingProvider(dimension=64)
    assert embedder.dimension == 64

    v1 = embedder.embed_text("Phishing alert from unknown domain")
    v2 = embedder.embed_text("Phishing alert from unknown domain")
    v3 = embedder.embed_text("Legitimate corporate communication")

    assert len(v1) == 64
    assert v1 == v2  # Deterministic
    assert v1 != v3  # Different inputs produce different vectors

    batch = embedder.embed_batch(["text 1", "text 2"])
    assert len(batch) == 2
    assert len(batch[0]) == 64


# --- 2. Vector Store Tests ---


def test_in_memory_vector_store_crud() -> None:
    store = InMemoryVectorStore()

    record = InvestigationMemory(
        memory_id="mem_inv_1",
        memory_type=MemoryType.INVESTIGATION,
        email_id="<test-1@msg>",
        subject="Invoice Notification",
        sender="billing@vendor.com",
        classification="Phishing",
        risk_level="high",
        summary="Phishing invoice scam",
        vector=(0.1, 0.2, 0.3),
        confidence_score=0.9,
    )

    store.insert(record)
    assert store.count() == 1

    fetched = store.get("mem_inv_1")
    assert fetched is not None
    assert fetched.memory_id == "mem_inv_1"

    updated = record.model_copy(update={"confidence_score": 0.99})
    store.update(updated)
    updated_record = store.get("mem_inv_1")
    assert updated_record is not None
    assert updated_record.confidence_score == 0.99

    assert store.delete("mem_inv_1") is True
    assert store.count() == 0


def test_vector_store_similarity_search_and_filters() -> None:
    store = InMemoryVectorStore()

    rec1 = InvestigationMemory(
        memory_id="inv_phish",
        memory_type=MemoryType.INVESTIGATION,
        email_id="<phish@test>",
        subject="Phishing Link Alert",
        sender="hacker@malicious.com",
        classification="Phishing",
        risk_level="high",
        summary="Credential phishing campaign",
        vector=(1.0, 0.0, 0.0),
        confidence_score=0.95,
        metadata={"category": "phishing"},
    )
    rec2 = InvestigationMemory(
        memory_id="inv_clean",
        memory_type=MemoryType.INVESTIGATION,
        email_id="<clean@test>",
        subject="Weekly All-Hands Meeting",
        sender="ceo@corp.com",
        classification="Clean",
        risk_level="low",
        summary="Internal clean meeting update",
        vector=(0.0, 1.0, 0.0),
        confidence_score=0.99,
        metadata={"category": "internal"},
    )

    store.insert(rec1)
    store.insert(rec2)

    # Search close to rec1 vector
    results = store.similarity_search(query_vector=(0.9, 0.1, 0.0), top_k=2)
    assert len(results) == 2
    assert results[0].memory_id == "inv_phish"
    assert results[0].similarity_score > 0.8

    # Search with metadata filter
    filtered = store.similarity_search(
        query_vector=(1.0, 0.0, 0.0),
        metadata_filters={"category": "internal"},
    )
    assert len(filtered) == 1
    assert filtered[0].memory_id == "inv_clean"


def test_vector_store_persistence_snapshot() -> None:
    with tempfile.TemporaryDirectory() as tmp_dir:
        snap_file = Path(tmp_dir) / "vector_store.json"
        store = InMemoryVectorStore(persistence_file=snap_file)

        rec = InvestigationMemory(
            memory_id="snap_1",
            memory_type=MemoryType.INVESTIGATION,
            email_id="<snap@test>",
            subject="Snapshot Test",
            sender="user@test.com",
            classification="Safe",
            risk_level="low",
            summary="Testing snapshot save/restore",
            vector=(0.5, 0.5),
        )
        store.insert(rec)
        assert snap_file.exists()

        # Restore into new store instance
        store2 = InMemoryVectorStore(persistence_file=snap_file)
        assert store2.count() == 1
        restored_record = store2.get("snap_1")
        assert isinstance(restored_record, InvestigationMemory)
        assert restored_record.subject == "Snapshot Test"


# --- 3. Memory Repositories Tests ---


def test_typed_memory_repositories() -> None:
    store = InMemoryVectorStore()
    embedder = DeterministicEmbeddingProvider(dimension=32)

    inv_repo = InvestigationRepository(store, embedder)

    inv_rec = InvestigationMemory(
        email_id="<inv@repo>",
        subject="Urgent Security Alert",
        sender="alert@security.org",
        classification="Phishing",
        risk_level="high",
        summary="Urgent security alert phishing email",
    )

    saved_inv = inv_repo.save_investigation(inv_rec)
    assert len(saved_inv.vector) == 32

    found = inv_repo.search_similar("security alert phishing", top_k=1)
    assert len(found) == 1
    assert found[0].memory_id == saved_inv.memory_id


# --- 4. Memory Retrieval Service Tests ---


def test_memory_retrieval_service_hybrid_search() -> None:
    store = InMemoryVectorStore()
    embedder = DeterministicEmbeddingProvider(dimension=32)
    retrieval = MemoryRetrievalService(store, embedder)

    inv_repo = InvestigationRepository(store, embedder)
    inv_repo.save_investigation(
        InvestigationMemory(
            email_id="<1>",
            subject="Wire Transfer Payment Notice",
            sender="billing@scam.com",
            classification="BEC Scam",
            risk_level="high",
            summary="Wire transfer invoice scam request",
        )
    )

    hybrid_res = retrieval.hybrid_search("wire transfer payment invoice", top_k=1)
    assert len(hybrid_res) == 1
    assert hybrid_res[0].similarity_score > 0.0

    cases = retrieval.find_similar_investigations(
        subject="Wire Transfer", sender="billing@scam.com"
    )
    assert len(cases) == 1


# --- 5. Learning Pipeline & Analyst Feedback Tests ---


def test_learning_pipeline_and_analyst_feedback() -> None:
    store = InMemoryVectorStore()
    embedder = DeterministicEmbeddingProvider(dimension=32)
    pipeline = LearningPipeline(store, embedder)
    feedback_sys = AnalystFeedbackSystem(store)

    state = AgentState.create(
        parsed_email=EmailInput(
            header=EmailHeader(
                message_id="<learn-1@test>",
                sender="spoofer@fakebank.com",
                recipients=["victim@corp.com"],
                subject="Account Deactivation Notice",
                sent_at="2026-07-28T12:00:00Z",
            ),
            body_text="Verify account at https://fakebank-login.com.",
            attachments=[
                EmailAttachment(
                    filename="document.zip",
                    content_type="application/zip",
                    size_bytes=1024,
                )
            ],
        )
    )

    ev = Evidence(
        category="url_reputation",
        title="Phishing URL Detected",
        description="Target domain fakebank-login.com is blacklisted.",
        severity=EvidenceSeverity.HIGH,
        source="url_tool",
        confidence=0.95,
    )
    state = state.model_copy(update={"evidence": state.evidence.add((ev,))})

    reasoning_engine = ReasoningEngine()
    verdict = reasoning_engine.reason(state)
    explain_engine = ExplainabilityEngine()
    report = explain_engine.generate_report(state, verdict)

    # Ingest investigation
    inv_mem = pipeline.ingest_investigation(state, verdict, report)
    assert inv_mem.memory_id in store._records

    # Check that sender, url, attachment, and evidence memories were created
    stats = store.count()
    assert stats >= 4  # Investigation, Evidence, Sender, URL, Attachment memories

    # Analyst Feedback
    fb = feedback_sys.submit_feedback(
        memory_id=inv_mem.memory_id,
        analyst_verdict="confirmed_phishing",
        analyst_notes="Verified by SOC analyst.",
    )
    assert fb.memory_id == inv_mem.memory_id
    updated_inv = store.get(inv_mem.memory_id)
    assert updated_inv is not None
    assert updated_inv.confidence_score == 0.99


# --- 6. Memory Manager (TTL Cleanup & Deduplication) Tests ---


def test_memory_manager_cleanup_and_deduplication() -> None:
    store = InMemoryVectorStore()
    manager = MemoryManager(store)

    rec1 = InvestigationMemory(
        memory_id="dup_1",
        memory_type=MemoryType.INVESTIGATION,
        email_id="<id-1>",
        subject="Dup",
        sender="s@s.com",
        classification="Phish",
        risk_level="high",
        summary="Summary",
        vector=(0.1, 0.2, 0.3),
        ttl_seconds=1,  # Expiration: 1 second
    )
    rec2 = InvestigationMemory(
        memory_id="dup_2",
        memory_type=MemoryType.INVESTIGATION,
        email_id="<id-2>",
        subject="Dup",
        sender="s@s.com",
        classification="Phish",
        risk_level="high",
        summary="Summary",
        vector=(0.1, 0.2, 0.3),  # Identical vector
    )

    store.insert(rec1)
    store.insert(rec2)
    assert store.count() == 2

    # Deduplicate identical vectors
    dedup_count = manager.deduplicate()
    assert dedup_count == 1
    assert store.count() == 1

    stats = manager.get_stats()
    assert stats.total_records == 1
