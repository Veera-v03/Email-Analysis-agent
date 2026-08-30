"""Production Semantic Incident RAG Engine orchestrating retrieval, prompt guard, and safe context assembly."""

from __future__ import annotations

import hashlib
from abc import ABC, abstractmethod
from datetime import UTC, datetime

from src.config.enterprise_config import settings
from src.config.logging import get_logger
from src.memory.embeddings.dense_embedding import DenseEmbeddingProvider
from src.memory.embeddings.embedding_provider import (
    DeterministicEmbeddingProvider,
    IEmbeddingProvider,
)
from src.memory.rag.context_builder import RAGContextBuilder
from src.memory.rag.models import (
    RAGResult,
    RAGRetrievalStatus,
    RetrievedIncidentContext,
    TrustClassification,
)
from src.memory.rag.prompt_guard import PromptGuard
from src.memory.rag.retriever import IncidentRetriever
from src.memory.rag.sanitizer import ContentSanitizer
from src.memory.storage.pgvector_store import PgVectorStore
from src.memory.storage.vector_store import (
    InMemoryVectorStore,
    IVectorStore,
)

logger = get_logger("scamon.memory.rag.engine")


class ISemanticIncidentRAG(ABC):
    """Abstract interface for Semantic Incident RAG subsystem."""

    @abstractmethod
    def retrieve(
        self,
        tenant_id: str,
        query: str,
        top_k: int | None = None,
        similarity_threshold: float | None = None,
    ) -> RAGResult:
        """Retrieve and assemble prompt injection-safe historical incident context."""


class SemanticIncidentRAGEngine(ISemanticIncidentRAG):
    """Production Semantic Incident RAG Engine with prompt-injection defense and tenant isolation."""

    def __init__(
        self,
        vector_store: IVectorStore | None = None,
        embedding_provider: IEmbeddingProvider | None = None,
        prompt_guard: PromptGuard | None = None,
        sanitizer: ContentSanitizer | None = None,
        context_builder: RAGContextBuilder | None = None,
    ) -> None:
        self._store = vector_store or PgVectorStore()
        self._embedder = embedding_provider or DenseEmbeddingProvider()
        self._prompt_guard = prompt_guard or PromptGuard()
        self._sanitizer = sanitizer or ContentSanitizer()
        self._builder = context_builder or RAGContextBuilder()
        self._retriever = IncidentRetriever(self._store, self._embedder)

    def retrieve(
        self,
        tenant_id: str,
        query: str,
        top_k: int | None = None,
        similarity_threshold: float | None = None,
    ) -> RAGResult:
        """Retrieve, sanitize, and assemble structured RAG context for downstream decision engine."""
        now_iso = datetime.now(UTC).isoformat()
        canon_query = query.strip()
        query_hash = hashlib.sha256(canon_query.encode("utf-8")).hexdigest()

        if not getattr(settings, "rag_enabled", True) or not canon_query:
            empty_block, chash = self._builder.build_context_block([])
            return RAGResult(
                tenant_id=tenant_id,
                query_hash=query_hash,
                retrieved_incidents=[],
                result_count=0,
                retrieval_status=RAGRetrievalStatus.EMPTY,
                degraded=False,
                context_hash=chash,
                generated_at=now_iso,
                formatted_context_block=empty_block,
            )

        k = top_k or getattr(settings, "rag_top_k", 5)
        thresh = (
            similarity_threshold
            if similarity_threshold is not None
            else getattr(settings, "rag_similarity_threshold", 0.70)
        )
        max_incident_len = getattr(settings, "rag_max_incident_chars", 800)
        max_context_len = getattr(settings, "rag_max_context_chars", 4000)

        # 1. Semantic Retrieval with strict tenant constraint
        raw_results = self._retriever.retrieve_raw_matches(
            tenant_id=tenant_id,
            query=canon_query,
            top_k=k,
            similarity_threshold=thresh,
        )

        # 2. Inspect, Sanitize, and Wrap into Structured Incident Contexts
        processed_incidents: list[RetrievedIncidentContext] = []
        for res in raw_results:
            rec = res.record
            # Extract summary text from record or metadata
            raw_summary = (
                rec.metadata.get("subject")
                or rec.metadata.get("summary")
                or str(rec.metadata)
            )

            # Detect prompt injection
            has_injection, matched_patterns = self._prompt_guard.inspect_text(str(raw_summary))

            # Sanitize content & redact credentials
            sanitized_text = self._sanitizer.sanitize(str(raw_summary), max_length=max_incident_len)

            incident_ctx = RetrievedIncidentContext(
                memory_id=res.memory_id or rec.memory_id,
                memory_type=res.memory_type.value if hasattr(res.memory_type, "value") else str(res.memory_type),
                similarity_score=res.similarity_score,
                sanitized_summary=sanitized_text,
                trust_level=TrustClassification.UNTRUSTED_HISTORICAL_DATA,
                injection_detected=has_injection,
                detected_injection_patterns=matched_patterns,
                source_reference=f"investigation_{rec.memory_id[:8]}",
                metadata={
                    k: v
                    for k, v in rec.metadata.items()
                    if k not in ("raw_email", "headers", "password", "token", "api_key")
                },
            )
            processed_incidents.append(incident_ctx)

        # 3. Assemble bounded XML context
        formatted_block, context_hash = self._builder.build_context_block(
            processed_incidents,
            max_context_chars=max_context_len,
        )

        # 4. Determine Health / Degraded Status
        is_embedding_degraded = getattr(self._embedder, "is_degraded", False)
        is_storage_degraded = getattr(self._store, "is_degraded", False)
        is_degraded = is_embedding_degraded or is_storage_degraded

        if is_embedding_degraded:
            status = RAGRetrievalStatus.DEGRADED_EMBEDDING
        elif is_storage_degraded:
            status = RAGRetrievalStatus.DEGRADED_STORAGE
        elif not processed_incidents:
            status = RAGRetrievalStatus.EMPTY
        else:
            status = RAGRetrievalStatus.CONNECTED

        return RAGResult(
            tenant_id=tenant_id,
            query_hash=query_hash,
            retrieved_incidents=processed_incidents,
            result_count=len(processed_incidents),
            retrieval_status=status,
            degraded=is_degraded,
            context_hash=context_hash,
            generated_at=now_iso,
            formatted_context_block=formatted_block,
        )
