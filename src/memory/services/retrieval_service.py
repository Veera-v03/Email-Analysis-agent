"""Memory retrieval service providing hybrid, semantic, keyword, and case-similarity search."""

from __future__ import annotations

from src.memory.embeddings.embedding_provider import IEmbeddingProvider
from src.memory.models.memory_models import (
    MemoryQuery,
    MemorySearchResult,
    MemoryType,
)
from src.memory.storage.vector_store import IVectorStore


class MemoryRetrievalService:
    """Provides high-level semantic, hybrid, and targeted case-similarity retrieval operations."""

    def __init__(
        self,
        vector_store: IVectorStore,
        embedding_provider: IEmbeddingProvider,
    ) -> None:
        self._store = vector_store
        self._embedder = embedding_provider

    def query(self, query: MemoryQuery) -> list[MemorySearchResult]:
        """Perform a structured query with semantic vector search, confidence, and metadata filtering."""
        query_vec = query.query_vector
        if not query_vec and query.query_text:
            query_vec = self._embedder.embed_text(query.query_text)

        if not query_vec:
            # Fallback zero vector
            query_vec = (0.0,) * self._embedder.dimension

        results = self._store.similarity_search(
            query_vector=query_vec,
            top_k=query.top_k,
            memory_type=query.memory_type,
            min_confidence=query.min_confidence,
            metadata_filters=query.metadata_filters,
        )

        # Time range filtering
        if query.time_range_start or query.time_range_end:
            filtered = []
            for res in results:
                t = res.record.created_at
                if query.time_range_start and t < query.time_range_start:
                    continue
                if query.time_range_end and t > query.time_range_end:
                    continue
                filtered.append(res)
            return filtered

        return results

    def hybrid_search(
        self,
        query_text: str,
        memory_type: MemoryType | None = None,
        top_k: int = 5,
        vector_weight: float = 0.7,
        keyword_weight: float = 0.3,
    ) -> list[MemorySearchResult]:
        """Perform hybrid search combining vector similarity score and keyword match score."""
        semantic_results = self.query(
            MemoryQuery(
                query_text=query_text,
                memory_type=memory_type,
                top_k=top_k * 2,
            )
        )

        keywords = [k.lower() for k in query_text.split() if len(k) > 2]
        scored_results: list[MemorySearchResult] = []

        for res in semantic_results:
            # Calculate keyword match score
            rec_dump = str(res.record.model_dump()).lower()
            kw_hits = sum(1 for kw in keywords if kw in rec_dump)
            kw_score = (kw_hits / len(keywords)) if keywords else 0.0

            combined_score = round(
                (res.similarity_score * vector_weight) + (kw_score * keyword_weight),
                4,
            )

            scored_results.append(
                res.model_copy(update={"similarity_score": combined_score})
            )

        scored_results.sort(key=lambda r: r.similarity_score, reverse=True)
        return scored_results[:top_k]

    # --- Targeted Case Similarity Helpers ---

    def find_similar_investigations(
        self,
        subject: str,
        sender: str,
        body_summary: str | None = None,
        top_k: int = 5,
    ) -> list[MemorySearchResult]:
        """Retrieve historical investigation runs matching email attributes."""
        query_str = f"{subject} {sender} {body_summary or ''}"
        return self.query(
            MemoryQuery(
                query_text=query_str,
                memory_type=MemoryType.INVESTIGATION,
                top_k=top_k,
                min_confidence=0.3,
            )
        )

    def find_similar_evidence(
        self,
        category: str,
        description: str,
        top_k: int = 5,
    ) -> list[MemorySearchResult]:
        """Retrieve past evidence items matching category and description."""
        query_str = f"{category} {description}"
        return self.query(
            MemoryQuery(
                query_text=query_str,
                memory_type=MemoryType.EVIDENCE,
                top_k=top_k,
                min_confidence=0.3,
            )
        )

    def find_similar_senders(
        self,
        sender_email: str,
        top_k: int = 5,
    ) -> list[MemorySearchResult]:
        """Retrieve sender reputation and interaction records."""
        return self.query(
            MemoryQuery(
                query_text=sender_email,
                memory_type=MemoryType.SENDER,
                top_k=top_k,
            )
        )

    def find_similar_urls(
        self,
        url: str,
        top_k: int = 5,
    ) -> list[MemorySearchResult]:
        """Retrieve matching URL threat intelligence records."""
        return self.query(
            MemoryQuery(
                query_text=url,
                memory_type=MemoryType.URL,
                top_k=top_k,
            )
        )

    def find_similar_attachments(
        self,
        filename: str,
        signature: str | None = None,
        top_k: int = 5,
    ) -> list[MemorySearchResult]:
        """Retrieve matching attachment signature records."""
        query_str = f"{filename} {signature or ''}"
        return self.query(
            MemoryQuery(
                query_text=query_str,
                memory_type=MemoryType.ATTACHMENT,
                top_k=top_k,
            )
        )
