"""Domain contracts and Pydantic models for the Memory & Learning subsystem."""

from __future__ import annotations

import uuid
from datetime import UTC, datetime
from enum import StrEnum
from typing import Any

from pydantic import (
    BaseModel,
    ConfigDict,
    Field,
    StrictBool,
    StrictInt,
    StrictStr,
    model_validator,
)


class MemoryType(StrEnum):
    """Enumeration of supported memory record classifications."""

    INVESTIGATION = "investigation"
    EVIDENCE = "evidence"
    THREAT = "threat"
    REPUTATION = "reputation"
    SENDER = "sender"
    URL = "url"
    ATTACHMENT = "attachment"
    PATTERN = "pattern"
    CASE = "case"


class BaseMemoryRecord(BaseModel):
    """Core memory record schema containing metadata, vector embeddings, and TTL policies."""

    model_config = ConfigDict(extra="forbid", strict=True, frozen=True)

    memory_id: StrictStr = Field(
        default_factory=lambda: f"mem_{uuid.uuid4().hex[:12]}",
        min_length=1,
        max_length=128,
    )
    memory_type: MemoryType = Field(default=MemoryType.INVESTIGATION)
    created_at: StrictStr = Field(
        default_factory=lambda: datetime.now(UTC).isoformat(),
        max_length=64,
    )
    updated_at: StrictStr = Field(
        default_factory=lambda: datetime.now(UTC).isoformat(),
        max_length=64,
    )
    ttl_seconds: StrictInt | None = Field(default=None, ge=1)
    confidence_score: float = Field(default=1.0, ge=0.0, le=1.0)
    metadata: dict[str, Any] = Field(default_factory=dict)
    vector: tuple[float, ...] = Field(default_factory=tuple)

    @model_validator(mode="before")
    @classmethod
    def preprocess_memory_record(cls, data: Any) -> Any:
        """Coerce list vectors and tuple parameters in strict mode."""
        if not isinstance(data, dict):
            return data

        mtype = data.get("memory_type")
        if isinstance(mtype, str):
            try:
                data["memory_type"] = MemoryType(mtype)
            except ValueError:
                pass

        vec = data.get("vector")
        if isinstance(vec, list):
            data["vector"] = tuple(vec)

        tools = data.get("executed_tools")
        if isinstance(tools, list):
            data["executed_tools"] = tuple(tools)

        inv_ids = data.get("investigation_ids")
        if isinstance(inv_ids, list):
            data["investigation_ids"] = tuple(inv_ids)

        return data


class InvestigationMemory(BaseMemoryRecord):
    """Memory representation of a complete email investigation run."""

    memory_type: MemoryType = Field(default=MemoryType.INVESTIGATION)
    email_id: StrictStr = Field(..., max_length=256)
    subject: StrictStr = Field(..., max_length=998)
    sender: StrictStr = Field(..., max_length=320)
    classification: StrictStr = Field(..., max_length=128)
    risk_level: StrictStr = Field(..., max_length=64)
    executed_tools: tuple[StrictStr, ...] = Field(default_factory=tuple)
    summary: StrictStr = Field(..., max_length=4096)


class EvidenceMemory(BaseMemoryRecord):
    """Memory record capturing structured evidence item findings."""

    memory_type: MemoryType = Field(default=MemoryType.EVIDENCE)
    evidence_id: StrictStr = Field(..., max_length=128)
    category: StrictStr = Field(..., max_length=128)
    title: StrictStr = Field(..., max_length=256)
    description: StrictStr = Field(..., max_length=4096)
    severity: StrictStr = Field(..., max_length=64)
    source_tool: StrictStr = Field(..., max_length=128)


class ThreatMemory(BaseMemoryRecord):
    """Captured threat indicators and known malicious patterns."""

    memory_type: MemoryType = Field(default=MemoryType.THREAT)
    threat_type: StrictStr = Field(..., max_length=128)
    indicator: StrictStr = Field(..., max_length=512)
    description: StrictStr = Field(..., max_length=2048)
    associated_campaign: StrictStr | None = Field(default=None, max_length=256)


class SenderMemory(BaseMemoryRecord):
    """Sender domain reputation and historical interaction tracking."""

    memory_type: MemoryType = Field(default=MemoryType.SENDER)
    sender_email: StrictStr = Field(..., max_length=320)
    domain: StrictStr = Field(..., max_length=256)
    reputation_score: float = Field(default=0.5, ge=0.0, le=1.0)
    incident_count: StrictInt = Field(default=0, ge=0)
    is_known_spoof: StrictBool = Field(default=False)


class URLMemory(BaseMemoryRecord):
    """Historical URL intelligence and reputation tracking."""

    memory_type: MemoryType = Field(default=MemoryType.URL)
    url: StrictStr = Field(..., max_length=2048)
    domain: StrictStr = Field(..., max_length=256)
    is_shortened: StrictBool = Field(default=False)
    is_malicious: StrictBool = Field(default=False)
    threat_category: StrictStr | None = Field(default=None, max_length=128)


class AttachmentMemory(BaseMemoryRecord):
    """Historical attachment metadata and signature tracking."""

    memory_type: MemoryType = Field(default=MemoryType.ATTACHMENT)
    filename: StrictStr = Field(..., max_length=255)
    extension: StrictStr = Field(..., max_length=64)
    file_hash: StrictStr | None = Field(default=None, max_length=128)
    is_malicious: StrictBool = Field(default=False)
    signature: StrictStr | None = Field(default=None, max_length=256)


class PatternMemory(BaseMemoryRecord):
    """Extracted heuristic or structural rules learned over time."""

    memory_type: MemoryType = Field(default=MemoryType.PATTERN)
    pattern_name: StrictStr = Field(..., max_length=128)
    pattern_rules: dict[str, Any] = Field(default_factory=dict)
    weight: float = Field(default=1.0, ge=0.0)
    occurrence_count: StrictInt = Field(default=1, ge=1)


class CaseMemory(BaseMemoryRecord):
    """Grouped investigation incident case folder."""

    memory_type: MemoryType = Field(default=MemoryType.CASE)
    case_id: StrictStr = Field(..., max_length=128)
    title: StrictStr = Field(..., max_length=256)
    investigation_ids: tuple[StrictStr, ...] = Field(default_factory=tuple)
    verdict: StrictStr = Field(..., max_length=128)


class MemoryQuery(BaseModel):
    """Query parameter container for retrieving memories."""

    model_config = ConfigDict(extra="forbid", strict=True, frozen=True)

    query_text: StrictStr | None = Field(default=None, max_length=1024)
    query_vector: tuple[float, ...] | None = Field(default=None)
    memory_type: MemoryType | None = Field(default=None)
    top_k: StrictInt = Field(default=5, ge=1, le=100)
    min_confidence: float = Field(default=0.0, ge=0.0, le=1.0)
    metadata_filters: dict[str, Any] = Field(default_factory=dict)
    time_range_start: StrictStr | None = Field(default=None, max_length=64)
    time_range_end: StrictStr | None = Field(default=None, max_length=64)

    @model_validator(mode="before")
    @classmethod
    def preprocess_memory_query(cls, data: Any) -> Any:
        """Truncate query_text to max 1024 chars to avoid validation errors."""
        if not isinstance(data, dict):
            return data
        qtext = data.get("query_text")
        if isinstance(qtext, str) and len(qtext) > 1024:
            data["query_text"] = qtext[:1024]
        return data


class MemorySearchResult(BaseModel):
    """Single matching record returned from vector or hybrid retrieval."""

    model_config = ConfigDict(extra="forbid", strict=True, frozen=True)

    memory_id: StrictStr
    memory_type: MemoryType
    similarity_score: float = Field(..., ge=-1.0, le=1.0)
    record: BaseMemoryRecord


class FeedbackRecord(BaseModel):
    """Analyst feedback record for confidence correction and learning."""

    model_config = ConfigDict(extra="forbid", strict=True, frozen=True)

    feedback_id: StrictStr = Field(
        default_factory=lambda: f"fb_{uuid.uuid4().hex[:12]}",
        min_length=1,
        max_length=128,
    )
    memory_id: StrictStr = Field(..., min_length=1, max_length=128)
    analyst_verdict: StrictStr = Field(
        ...,
        description="Analyst verdict: confirmed_phishing, false_positive, false_negative, safe_email",
    )
    analyst_notes: StrictStr = Field(default="", max_length=4096)
    timestamp: StrictStr = Field(
        default_factory=lambda: datetime.now(UTC).isoformat(),
        max_length=64,
    )


class MemoryStats(BaseModel):
    """Aggregated operational statistics of the memory store."""

    model_config = ConfigDict(extra="forbid", strict=True, frozen=True)

    total_records: StrictInt = Field(ge=0)
    type_counts: dict[StrictStr, StrictInt] = Field(default_factory=dict)
    storage_bytes: StrictInt = Field(ge=0)
    oldest_timestamp: StrictStr | None = None
    newest_timestamp: StrictStr | None = None
