# Phase 7: Memory & Learning Intelligence Architecture

## Overview
Phase 7 introduces an enterprise-grade Memory & Learning Subsystem to the Email Analysis Agent. The memory layer acts as a shared, persistent knowledge store that retains investigation outcomes, extracted evidence, threat indicators, sender/URL/attachment reputation, and learned heuristic patterns over time.

## Architecture
The Memory & Learning subsystem follows Clean Architecture, DDD, and SOLID engineering principles:

```
src/memory/
├── models/             # Domain contracts for MemoryRecords, Queries, SearchResults, Stats
├── embeddings/         # IEmbeddingProvider, Deterministic & Mock vector generators
├── storage/            # IVectorStore, InMemoryVectorStore (with snapshot persistence)
├── repositories/       # Typed repositories (Investigation, Evidence, Threat, Sender, URL, Attachment, Pattern)
├── services/           # RetrievalService (Hybrid & Semantic), LearningPipeline, AnalystFeedbackSystem
├── management/         # MemoryManager (TTL retention cleanup, Deduplication, Stats)
└── __init__.py         # Subsystem exports
```

## Key Components

### 1. Memory Models (`src/memory/models/memory_models.py`)
Provides strictly typed, Pydantic v2 schemas with `extra="forbid"` and `strict=True` for:
- `InvestigationMemory`: Email metadata, classification, risk level, executed tool sequence, summary.
- `EvidenceMemory`: Category, title, description, severity, source tool, confidence score.
- `ThreatMemory`: Threat indicator, threat type, associated campaign name.
- `SenderMemory`: Sender email, domain, reputation score, incident count, spoofing status.
- `URLMemory`: URL, domain, shortening status, malicious flag, threat category.
- `AttachmentMemory`: Filename, extension, hash, signature, malicious flag.
- `PatternMemory`: Rule name, rules dictionary, heuristic weight, occurrence count.
- `CaseMemory`: Incident folder grouping multiple related investigations.

### 2. Embeddings (`src/memory/embeddings/embedding_provider.py`)
- `IEmbeddingProvider`: Abstract interface for dense vector generation.
- `DeterministicEmbeddingProvider`: Feature vectorizer mapping text to fixed-dimension L2 unit vectors using token/character n-grams and hashing (zero external dependency).

### 3. Vector Storage (`src/memory/storage/vector_store.py`)
- `IVectorStore`: Abstract vector database contract supporting `insert`, `update`, `delete`, `get`, `similarity_search`, and `count`.
- `InMemoryVectorStore`: High-performance cosine similarity search with type filtering, min-confidence filtering, metadata filtering, and JSON snapshot disk persistence.

### 4. Typed Repositories (`src/memory/repositories/memory_repository.py`)
Generic `BaseMemoryRepository[T]` providing type-safe CRUD and similarity search for each memory model class.

### 5. Memory Retrieval Service (`src/memory/services/retrieval_service.py`)
- **Semantic Search**: Vector similarity matching using cosine distance.
- **Hybrid Search**: Weighted combination of vector similarity score ($0.7$) and keyword match ratio ($0.3$).
- **Case Similarity Queries**: Targeted helpers (`find_similar_investigations`, `find_similar_evidence`, `find_similar_senders`, `find_similar_urls`, `find_similar_attachments`).

### 6. Learning Pipeline (`src/memory/services/learning_pipeline.py`)
In-flight and post-investigation learning pipeline that ingests completed `AgentState`, `ReasoningOutput`, and `FinalReport` records to automatically populate all entity repositories and pattern stores.

### 7. Analyst Feedback System (`src/memory/services/feedback_system.py`)
Enables security analysts to submit feedback (`confirmed_phishing`, `false_positive`, `false_negative`, `safe_email`), updating confidence scores and reputation flags in real time.

### 8. Memory Management (`src/memory/management/memory_manager.py`)
Provides automated TTL retention purging, vector content deduplication, and operational `MemoryStats` reporting.

## Testing & Verification
Full unit and integration coverage implemented in `tests/test_phase7_memory.py`.
Run tests via:
```bash
pytest tests/test_phase7_memory.py
```
