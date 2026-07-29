"""Analyzer-independent evidence collection data contracts."""

from __future__ import annotations

import uuid
from datetime import UTC, datetime
from enum import StrEnum
from typing import Any

from pydantic import BaseModel, ConfigDict, Field, StrictStr

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
        default_factory=lambda: f"ev_{uuid.uuid4().hex[:12]}",
        min_length=1,
        max_length=MAX_EVIDENCE_IDENTIFIER_LENGTH,
    )
    evidence_type: StrictStr = Field(
        default="general",
        min_length=1,
        max_length=MAX_EVIDENCE_TYPE_LENGTH,
    )
    category: StrictStr = Field(
        default="general",
        min_length=1,
        max_length=MAX_EVIDENCE_TYPE_LENGTH,
    )
    title: StrictStr = Field(
        min_length=1,
        max_length=MAX_EVIDENCE_TITLE_LENGTH,
    )
    description: StrictStr = Field(
        min_length=1,
        max_length=MAX_EVIDENCE_DESCRIPTION_LENGTH,
    )
    severity: EvidenceSeverity
    source: StrictStr = Field(
        min_length=1,
        max_length=MAX_EVIDENCE_SOURCE_LENGTH,
    )
    confidence: float | None = Field(default=None, ge=0.0, le=1.0)
    recommendation: StrictStr | None = Field(default=None, max_length=1024)
    metadata: dict[str, Any] = Field(default_factory=dict)
    timestamp: StrictStr = Field(
        default_factory=lambda: datetime.now(UTC).isoformat(),
        max_length=64,
    )

    def to_dict(self) -> dict[str, Any]:
        """Dump the evidence model to a Python dictionary."""
        return self.model_dump()

    def to_json(self) -> str:
        """Dump the evidence model to a JSON string."""
        return self.model_dump_json()

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> Evidence:
        """Parse an Evidence instance from a dictionary."""
        return cls.model_validate(data)

    @classmethod
    def from_json(cls, json_str: str) -> Evidence:
        """Parse an Evidence instance from a JSON string."""
        return cls.model_validate_json(json_str)


class EvidenceCollection(BaseModel):
    """Contain evidence items emitted during one bounded analysis operation."""

    model_config = ConfigDict(extra="forbid", strict=True, frozen=True)

    items: tuple[Evidence, ...] = Field(default=())

    def add(
        self,
        item: Evidence | tuple[Evidence, ...] | list[Evidence],
    ) -> EvidenceCollection:
        """Return a new EvidenceCollection with additional item(s) appended."""
        new_items = (item,) if isinstance(item, Evidence) else tuple(item)
        return self.model_copy(update={"items": self.items + new_items})

    def filter_by_severity(self, severity: EvidenceSeverity) -> tuple[Evidence, ...]:
        """Filter evidence items matching a specific severity level."""
        return tuple(ev for ev in self.items if ev.severity is severity)

    def filter_by_source(self, source: str) -> tuple[Evidence, ...]:
        """Filter evidence items matching a specific source tool."""
        return tuple(ev for ev in self.items if ev.source == source)

    def filter_by_category(self, category: str) -> tuple[Evidence, ...]:
        """Filter evidence items matching a category or evidence_type."""
        return tuple(
            ev
            for ev in self.items
            if ev.category == category or ev.evidence_type == category
        )

    def to_dict(self) -> dict[str, Any]:
        """Dump the collection to a Python dictionary."""
        return self.model_dump()

    def to_json(self) -> str:
        """Dump the collection to a JSON string."""
        return self.model_dump_json()

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> EvidenceCollection:
        """Parse an EvidenceCollection instance from a dictionary."""
        return cls.model_validate(data)

    @classmethod
    def from_json(cls, json_str: str) -> EvidenceCollection:
        """Parse an EvidenceCollection instance from a JSON string."""
        return cls.model_validate_json(json_str)
