"""Analyzer-independent evidence collection data contracts."""

from __future__ import annotations

from enum import StrEnum

from pydantic import BaseModel, ConfigDict, Field, JsonValue, StrictStr

MAX_EVIDENCE_IDENTIFIER_LENGTH = 128
MAX_EVIDENCE_TYPE_LENGTH = 128
MAX_EVIDENCE_TITLE_LENGTH = 256
MAX_EVIDENCE_DESCRIPTION_LENGTH = 4_096
MAX_EVIDENCE_SOURCE_LENGTH = 256


class EvidenceSeverity(StrEnum):
    """Describe the operational prominence of one piece of evidence.

    Severity is a presentation and triage attribute only. It is not a risk
    score, probability, or final security classification.
    """

    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class Evidence(BaseModel):
    """Represent one self-contained, analyzer-independent evidence record."""

    model_config = ConfigDict(extra="forbid", strict=True, frozen=True)

    evidence_id: StrictStr = Field(
        min_length=1,
        max_length=MAX_EVIDENCE_IDENTIFIER_LENGTH,
    )
    evidence_type: StrictStr = Field(min_length=1, max_length=MAX_EVIDENCE_TYPE_LENGTH)
    title: StrictStr = Field(min_length=1, max_length=MAX_EVIDENCE_TITLE_LENGTH)
    description: StrictStr = Field(
        min_length=1,
        max_length=MAX_EVIDENCE_DESCRIPTION_LENGTH,
    )
    severity: EvidenceSeverity
    source: StrictStr = Field(min_length=1, max_length=MAX_EVIDENCE_SOURCE_LENGTH)
    metadata: dict[StrictStr, JsonValue] = Field(default_factory=dict)


class EvidenceCollection(BaseModel):
    """Contain evidence items emitted during one bounded analysis operation."""

    model_config = ConfigDict(extra="forbid", strict=True, frozen=True)

    items: tuple[Evidence, ...] = Field(default=())
