"""Typed memory repositories managing CRUD and vector index operations for each memory type."""

from __future__ import annotations

from typing import Any, Generic, TypeVar

from src.memory.embeddings.embedding_provider import IEmbeddingProvider
from src.memory.models.memory_models import (
    AttachmentMemory,
    BaseMemoryRecord,
    EvidenceMemory,
    InvestigationMemory,
    MemorySearchResult,
    MemoryType,
    PatternMemory,
    SenderMemory,
    ThreatMemory,
    URLMemory,
)
from src.memory.storage.vector_store import IVectorStore

T = TypeVar("T", bound=BaseMemoryRecord)


class BaseMemoryRepository(Generic[T]):
    """Base generic repository abstracting vector storage and embedding for a specific memory model."""

    def __init__(
        self,
        vector_store: IVectorStore,
        embedding_provider: IEmbeddingProvider,
        memory_type: MemoryType,
        model_class: type[T],
    ) -> None:
        self._store = vector_store
        self._embedder = embedding_provider
        self._memory_type = memory_type
        self._model_class = model_class

    def save(self, record: T, text_for_embedding: str | None = None) -> T:
        """Save record, computing vector embedding if text is supplied or available."""
        vec = record.vector
        if text_for_embedding and not vec:
            vec = self._embedder.embed_text(text_for_embedding)

        updated_record = record.model_copy(update={"vector": vec})
        self._store.insert(updated_record)
        return updated_record

    def get(self, memory_id: str) -> T | None:
        """Fetch record by memory_id."""
        raw = self._store.get(memory_id)
        if raw and isinstance(raw, self._model_class):
            return raw
        elif raw:
            return self._model_class.model_validate(raw.model_dump())
        return None

    def delete(self, memory_id: str) -> bool:
        """Delete record by memory_id."""
        return self._store.delete(memory_id)

    def search_similar(
        self,
        query_text: str,
        top_k: int = 5,
        min_confidence: float = 0.0,
        metadata_filters: dict[str, Any] | None = None,
    ) -> list[MemorySearchResult]:
        """Perform similarity search using embedded query text."""
        query_vector = self._embedder.embed_text(query_text)
        return self._store.similarity_search(
            query_vector=query_vector,
            top_k=top_k,
            memory_type=self._memory_type,
            min_confidence=min_confidence,
            metadata_filters=metadata_filters,
        )


class InvestigationRepository(BaseMemoryRepository[InvestigationMemory]):
    """Repository managing historical investigation memory records."""

    def __init__(
        self, vector_store: IVectorStore, embedding_provider: IEmbeddingProvider
    ) -> None:
        super().__init__(
            vector_store=vector_store,
            embedding_provider=embedding_provider,
            memory_type=MemoryType.INVESTIGATION,
            model_class=InvestigationMemory,
        )

    def save_investigation(self, record: InvestigationMemory) -> InvestigationMemory:
        """Extract text summary and save investigation record."""
        text = (
            f"{record.subject} {record.sender} {record.summary} {record.classification}"
        )
        return self.save(record, text_for_embedding=text)


class EvidenceRepository(BaseMemoryRepository[EvidenceMemory]):
    """Repository managing structured evidence memory records."""

    def __init__(
        self, vector_store: IVectorStore, embedding_provider: IEmbeddingProvider
    ) -> None:
        super().__init__(
            vector_store=vector_store,
            embedding_provider=embedding_provider,
            memory_type=MemoryType.EVIDENCE,
            model_class=EvidenceMemory,
        )

    def save_evidence(self, record: EvidenceMemory) -> EvidenceMemory:
        """Extract evidence text and save record."""
        text = f"{record.category} {record.title} {record.description}"
        return self.save(record, text_for_embedding=text)


class ThreatRepository(BaseMemoryRepository[ThreatMemory]):
    """Repository managing threat indicator and campaign memory records."""

    def __init__(
        self, vector_store: IVectorStore, embedding_provider: IEmbeddingProvider
    ) -> None:
        super().__init__(
            vector_store=vector_store,
            embedding_provider=embedding_provider,
            memory_type=MemoryType.THREAT,
            model_class=ThreatMemory,
        )

    def save_threat(self, record: ThreatMemory) -> ThreatMemory:
        """Extract threat details and save record."""
        text = f"{record.threat_type} {record.indicator} {record.description}"
        return self.save(record, text_for_embedding=text)


class SenderRepository(BaseMemoryRepository[SenderMemory]):
    """Repository managing sender and domain reputation records."""

    def __init__(
        self, vector_store: IVectorStore, embedding_provider: IEmbeddingProvider
    ) -> None:
        super().__init__(
            vector_store=vector_store,
            embedding_provider=embedding_provider,
            memory_type=MemoryType.SENDER,
            model_class=SenderMemory,
        )

    def save_sender(self, record: SenderMemory) -> SenderMemory:
        """Extract sender details and save record."""
        text = f"{record.sender_email} {record.domain}"
        return self.save(record, text_for_embedding=text)


class URLRepository(BaseMemoryRepository[URLMemory]):
    """Repository managing historical URL reputation records."""

    def __init__(
        self, vector_store: IVectorStore, embedding_provider: IEmbeddingProvider
    ) -> None:
        super().__init__(
            vector_store=vector_store,
            embedding_provider=embedding_provider,
            memory_type=MemoryType.URL,
            model_class=URLMemory,
        )

    def save_url(self, record: URLMemory) -> URLMemory:
        """Extract URL details and save record."""
        text = f"{record.url} {record.domain} {record.threat_category or ''}"
        return self.save(record, text_for_embedding=text)


class AttachmentRepository(BaseMemoryRepository[AttachmentMemory]):
    """Repository managing historical attachment signature records."""

    def __init__(
        self, vector_store: IVectorStore, embedding_provider: IEmbeddingProvider
    ) -> None:
        super().__init__(
            vector_store=vector_store,
            embedding_provider=embedding_provider,
            memory_type=MemoryType.ATTACHMENT,
            model_class=AttachmentMemory,
        )

    def save_attachment(self, record: AttachmentMemory) -> AttachmentMemory:
        """Extract attachment details and save record."""
        text = f"{record.filename} {record.extension} {record.file_hash or ''} {record.signature or ''}"
        return self.save(record, text_for_embedding=text)


class PatternRepository(BaseMemoryRepository[PatternMemory]):
    """Repository managing learned heuristic patterns."""

    def __init__(
        self, vector_store: IVectorStore, embedding_provider: IEmbeddingProvider
    ) -> None:
        super().__init__(
            vector_store=vector_store,
            embedding_provider=embedding_provider,
            memory_type=MemoryType.PATTERN,
            model_class=PatternMemory,
        )

    def save_pattern(self, record: PatternMemory) -> PatternMemory:
        """Extract pattern details and save record."""
        text = f"{record.pattern_name} {record.pattern_rules}"
        return self.save(record, text_for_embedding=text)
