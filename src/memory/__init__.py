"""Phase 7 - Memory & Learning Intelligence Subsystem Exports."""

from src.memory.embeddings import (
    DeterministicEmbeddingProvider,
    IEmbeddingProvider,
    MockEmbeddingProvider,
)
from src.memory.management import MemoryManager
from src.memory.models import (
    AttachmentMemory,
    BaseMemoryRecord,
    CaseMemory,
    EvidenceMemory,
    FeedbackRecord,
    InvestigationMemory,
    MemoryQuery,
    MemorySearchResult,
    MemoryStats,
    MemoryType,
    PatternMemory,
    SenderMemory,
    ThreatMemory,
    URLMemory,
)
from src.memory.repositories import (
    AttachmentRepository,
    BaseMemoryRepository,
    EvidenceRepository,
    InvestigationRepository,
    PatternRepository,
    SenderRepository,
    ThreatRepository,
    URLRepository,
)
from src.memory.services import (
    AnalystFeedbackSystem,
    LearningPipeline,
    MemoryRetrievalService,
)
from src.memory.storage import InMemoryVectorStore, IVectorStore

__all__ = [
    # Models
    "MemoryType",
    "BaseMemoryRecord",
    "InvestigationMemory",
    "EvidenceMemory",
    "ThreatMemory",
    "SenderMemory",
    "URLMemory",
    "AttachmentMemory",
    "PatternMemory",
    "CaseMemory",
    "MemoryQuery",
    "MemorySearchResult",
    "FeedbackRecord",
    "MemoryStats",
    # Embeddings
    "IEmbeddingProvider",
    "DeterministicEmbeddingProvider",
    "MockEmbeddingProvider",
    # Storage
    "IVectorStore",
    "InMemoryVectorStore",
    # Repositories
    "BaseMemoryRepository",
    "InvestigationRepository",
    "EvidenceRepository",
    "ThreatRepository",
    "SenderRepository",
    "URLRepository",
    "AttachmentRepository",
    "PatternRepository",
    # Services
    "MemoryRetrievalService",
    "LearningPipeline",
    "AnalystFeedbackSystem",
    # Management
    "MemoryManager",
]
