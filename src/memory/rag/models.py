"""Data Transfer Objects and enumerations for Semantic Incident RAG subsystem."""

from __future__ import annotations

from enum import StrEnum
from typing import Any

from pydantic import Field

from src.common.models import BaseDTO


class TrustClassification(StrEnum):
    """Immutable classification declaring retrieved content untrusted."""

    UNTRUSTED_HISTORICAL_DATA = "UNTRUSTED_HISTORICAL_DATA"
    UNTRUSTED_EXTERNAL_DATA = "UNTRUSTED_EXTERNAL_DATA"


class RAGRetrievalStatus(StrEnum):
    """Explicit status tracking retrieval backend state."""

    CONNECTED = "CONNECTED"
    DEGRADED_EMBEDDING = "DEGRADED_EMBEDDING"
    DEGRADED_STORAGE = "DEGRADED_STORAGE"
    EMPTY = "EMPTY"
    ERROR = "ERROR"


class RetrievedIncidentContext(BaseDTO):
    """Structured, sanitized representation of a single historical incident for RAG injection."""

    memory_id: str = Field(description="Unique historical memory identifier")
    memory_type: str = Field(description="Classification type of stored memory")
    similarity_score: float = Field(ge=0.0, le=1.0, description="Cosine similarity score (0.0 - 1.0)")
    sanitized_summary: str = Field(description="Redacted and sanitized human-readable summary")
    trust_level: TrustClassification = Field(
        default=TrustClassification.UNTRUSTED_HISTORICAL_DATA,
        description="Explicit trust boundary indicator",
    )
    injection_detected: bool = Field(
        default=False,
        description="True if prompt injection patterns were discovered and neutralized",
    )
    detected_injection_patterns: list[str] = Field(
        default_factory=list,
        description="Names of prompt injection rules triggered",
    )
    source_reference: str = Field(description="Audit or investigation source reference")
    metadata: dict[str, Any] = Field(default_factory=dict, description="Filtered structural metadata")


class RAGResult(BaseDTO):
    """Validated immutable output of Semantic Incident RAG Engine."""

    tenant_id: str = Field(description="Tenant UUID boundary for retrieval")
    query_hash: str = Field(description="SHA-256 hash of canonicalized query text")
    retrieved_incidents: list[RetrievedIncidentContext] = Field(
        default_factory=list,
        description="Ordered, deduplicated, and sanitized incident contexts",
    )
    result_count: int = Field(ge=0, description="Total number of incidents returned")
    retrieval_status: RAGRetrievalStatus = Field(description="Backend execution health status")
    degraded: bool = Field(default=False, description="True if operating in fallback degraded mode")
    context_hash: str = Field(description="SHA-256 deterministic hash of generated RAG context block")
    generated_at: str = Field(description="ISO-8601 generation timestamp")
    formatted_context_block: str = Field(
        description="Bounded, XML-delimited prompt injection-safe context string"
    )
