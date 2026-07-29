"""Evidence builder and evidence aggregator framework components."""

from __future__ import annotations

import uuid
from datetime import UTC, datetime
from typing import Any, Self

from src.models.agent import ToolEvidence
from src.models.evidence import Evidence, EvidenceCollection, EvidenceSeverity

SEVERITY_WEIGHTS: dict[EvidenceSeverity, int] = {
    EvidenceSeverity.CRITICAL: 4,
    EvidenceSeverity.HIGH: 3,
    EvidenceSeverity.MEDIUM: 2,
    EvidenceSeverity.LOW: 1,
    EvidenceSeverity.INFO: 0,
}


class EvidenceBuilder:
    """Fluent builder for constructing immutable Evidence objects."""

    def __init__(self) -> None:
        self._evidence_id: str = f"ev_{uuid.uuid4().hex[:12]}"
        self._source: str = "agent"
        self._category: str = "general"
        self._title: str = "Evidence Observation"
        self._description: str = "Automated tool observation"
        self._severity: EvidenceSeverity = EvidenceSeverity.INFO
        self._confidence: float | None = None
        self._recommendation: str | None = None
        self._metadata: dict[str, Any] = {}
        self._timestamp: str = datetime.now(UTC).isoformat()

    @classmethod
    def create(cls) -> Self:
        """Create a new EvidenceBuilder instance."""
        return cls()

    def with_id(self, evidence_id: str) -> Self:
        """Set evidence ID."""
        self._evidence_id = evidence_id
        return self

    def with_source(self, source: str) -> Self:
        """Set source tool name."""
        self._source = source
        return self

    def with_category(self, category: str) -> Self:
        """Set evidence category / type."""
        self._category = category
        return self

    def with_title(self, title: str) -> Self:
        """Set evidence title."""
        self._title = title
        return self

    def with_description(self, description: str) -> Self:
        """Set detailed evidence description."""
        self._description = description
        return self

    def with_severity(self, severity: EvidenceSeverity | str) -> Self:
        """Set evidence severity level."""
        if isinstance(severity, str):
            self._severity = EvidenceSeverity(severity.lower())
        else:
            self._severity = severity
        return self

    def with_confidence(self, confidence: float | None) -> Self:
        """Set confidence score (0.0 to 1.0)."""
        self._confidence = confidence
        return self

    def with_recommendation(self, recommendation: str | None) -> Self:
        """Set actionable recommendation text."""
        self._recommendation = recommendation
        return self

    def with_metadata(self, metadata: dict[str, Any]) -> Self:
        """Attach structured metadata dictionary."""
        self._metadata = dict(metadata)
        return self

    def add_metadata(self, key: str, value: Any) -> Self:
        """Add a single metadata key-value pair."""
        self._metadata[key] = value
        return self

    def build(self) -> Evidence:
        """Build and return an immutable Evidence instance."""
        return Evidence(
            evidence_id=self._evidence_id,
            source=self._source,
            category=self._category,
            evidence_type=self._category,
            title=self._title,
            description=self._description,
            severity=self._severity,
            confidence=self._confidence,
            recommendation=self._recommendation,
            metadata=self._metadata,
            timestamp=self._timestamp,
        )


class EvidenceAggregator:
    """Aggregate, deduplicate, and order evidence items from multiple tools."""

    @classmethod
    def from_tool_evidence(
        cls,
        tool_evidence: ToolEvidence,
        source_tool: str = "agent_tool",
    ) -> Evidence:
        """Convert a ToolEvidence instance into a standardized Evidence object."""
        meta = dict(tool_evidence.metadata)
        severity_str = str(meta.get("severity", "info")).lower()
        try:
            severity = EvidenceSeverity(severity_str)
        except ValueError:
            severity = EvidenceSeverity.INFO

        confidence = meta.get("confidence")
        if not isinstance(confidence, (int, float)):
            confidence = None
        else:
            confidence = float(confidence)

        return Evidence(
            source=source_tool,
            category=tool_evidence.category,
            evidence_type=tool_evidence.category,
            title=tool_evidence.category.replace("_", " ").title(),
            description=tool_evidence.detail,
            severity=severity,
            confidence=confidence,
            metadata=meta,
        )

    @classmethod
    def aggregate(
        cls,
        items: list[Evidence | ToolEvidence | tuple[Evidence | ToolEvidence, ...]],
        default_source: str = "agent",
    ) -> EvidenceCollection:
        """Aggregate, deduplicate, and sort evidence items into an EvidenceCollection."""
        flat_list: list[Evidence] = []

        for item in items:
            if isinstance(item, (tuple, list)):
                for sub in item:
                    if isinstance(sub, Evidence):
                        flat_list.append(sub)
                    elif isinstance(sub, ToolEvidence):
                        flat_list.append(
                            cls.from_tool_evidence(sub, source_tool=default_source)
                        )
            elif isinstance(item, Evidence):
                flat_list.append(item)
            elif isinstance(item, ToolEvidence):
                flat_list.append(
                    cls.from_tool_evidence(item, source_tool=default_source)
                )

        # Deduplicate based on (source, category, title, description)
        seen: set[tuple[str, str, str, str]] = set()
        unique_list: list[Evidence] = []
        for ev in flat_list:
            key = (ev.source, ev.category, ev.title, ev.description)
            if key not in seen:
                seen.add(key)
                unique_list.append(ev)

        # Sort by severity descending (highest severity first), then timestamp
        unique_list.sort(
            key=lambda ev: (SEVERITY_WEIGHTS.get(ev.severity, 0), ev.timestamp),
            reverse=True,
        )

        return EvidenceCollection(items=tuple(unique_list))
