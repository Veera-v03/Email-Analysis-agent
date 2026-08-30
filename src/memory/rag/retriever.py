"""Tenant-isolated semantic similarity retriever with deduplication and threshold filtering."""

from __future__ import annotations

from typing import Any

from src.config.logging import get_logger
from src.memory.embeddings.embedding_provider import IEmbeddingProvider
from src.memory.models.memory_models import MemorySearchResult
from src.memory.storage.vector_store import IVectorStore

logger = get_logger("scamon.memory.rag.retriever")


class IncidentRetriever:
    """Performs tenant-constrained semantic search across historical incident memory."""

    def __init__(
        self,
        vector_store: IVectorStore,
        embedding_provider: IEmbeddingProvider,
    ) -> None:
        self._store = vector_store
        self._embedder = embedding_provider

    def retrieve_raw_matches(
        self,
        tenant_id: str,
        query: str,
        top_k: int = 5,
        similarity_threshold: float = 0.70,
    ) -> list[MemorySearchResult]:
        """Perform semantic search strictly bounded to tenant_id with threshold filtering and deduplication."""
        canon_query = query.strip()
        if not canon_query:
            return []

        # 1. Generate query vector
        try:
            query_vector = self._embedder.embed_text(canon_query)
        except Exception as exc:
            logger.warning("Embedding generation error during RAG retrieval: %s", exc)
            return []

        # 2. Query Vector Store with STRICT tenant filter
        try:
            search_results = self._store.similarity_search(
                query_vector=query_vector,
                top_k=top_k * 2,  # Fetch extra to account for threshold filtering and deduplication
                metadata_filters={"tenant_id": tenant_id},
            )
        except Exception as exc:
            logger.warning("Vector storage search error during RAG retrieval: %s", exc)
            return []

        # 3. Apply relevance threshold & deduplicate by memory_id
        deduped: dict[str, MemorySearchResult] = {}
        for res in search_results:
            if res.similarity_score < similarity_threshold:
                continue

            mem_id = res.memory_id or res.record.memory_id
            if mem_id not in deduped or res.similarity_score > deduped[mem_id].similarity_score:
                deduped[mem_id] = res

        # 4. Sort descending by similarity score
        sorted_results = sorted(
            deduped.values(),
            key=lambda r: r.similarity_score,
            reverse=True,
        )

        return sorted_results[:top_k]
