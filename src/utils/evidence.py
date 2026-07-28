"""Reusable, thread-safe evidence emission and collection utilities."""

from __future__ import annotations

import json
from collections.abc import Mapping
from hashlib import sha256
from threading import RLock
from typing import Protocol, runtime_checkable

from pydantic import JsonValue, TypeAdapter

from src.models.evidence import Evidence, EvidenceCollection, EvidenceSeverity

METADATA_ADAPTER: TypeAdapter[dict[str, JsonValue]] = TypeAdapter(dict[str, JsonValue])
EVIDENCE_DIGEST_LENGTH = 24


@runtime_checkable
class EvidenceSink(Protocol):
    """Accept independently created evidence records from an analyzer."""

    def record(self, evidence: Evidence) -> None:
        """Record one evidence item for the current analysis operation."""


@runtime_checkable
class EvidenceEmitter(Protocol):
    """Emit evidence through an injected sink without owning collection state."""

    def emit_evidence(self, sink: EvidenceSink) -> None:
        """Emit independently derived evidence to the supplied sink."""


class EvidenceCollector:
    """Collect evidence records for a single operation with stable opaque IDs."""

    def __init__(self) -> None:
        """Create an empty, thread-safe evidence collector."""
        self._items: list[Evidence] = []
        self._sequence = 0
        self._lock = RLock()

    def emit(
        self,
        *,
        evidence_type: str,
        title: str,
        description: str,
        severity: EvidenceSeverity,
        source: str,
        metadata: Mapping[str, JsonValue] | None = None,
    ) -> Evidence:
        """Create, record, and return one validated evidence item.

        Args:
            evidence_type: Stable category identifying the evidence observation.
            title: Concise human-readable evidence title.
            description: Detailed human-readable observation description.
            severity: Operational prominence, not a risk classification.
            source: Analyzer or component that produced the observation.
            metadata: JSON-compatible structured context for the observation.

        Returns:
            The validated evidence record that was added to this collector.
        """
        metadata_payload = METADATA_ADAPTER.validate_python(dict(metadata or {}))
        with self._lock:
            self._sequence += 1
            evidence = Evidence(
                evidence_id=self._evidence_id(
                    self._sequence,
                    evidence_type,
                    title,
                    description,
                    severity,
                    source,
                    metadata_payload,
                ),
                evidence_type=evidence_type,
                title=title,
                description=description,
                severity=severity,
                source=source,
                metadata=metadata_payload,
            )
            self._items.append(evidence)
            return evidence

    def record(self, evidence: Evidence) -> None:
        """Record an independently constructed validated evidence item.

        Args:
            evidence: Validated evidence emitted by another component.
        """
        with self._lock:
            self._items.append(evidence)

    def snapshot(self) -> EvidenceCollection:
        """Return an immutable model snapshot of all collected evidence."""
        with self._lock:
            return EvidenceCollection(items=tuple(self._items))

    @staticmethod
    def _evidence_id(
        sequence: int,
        evidence_type: str,
        title: str,
        description: str,
        severity: EvidenceSeverity,
        source: str,
        metadata: dict[str, JsonValue],
    ) -> str:
        """Create a stable opaque ID that does not expose metadata in the identifier."""
        canonical_metadata = json.dumps(
            metadata,
            ensure_ascii=False,
            separators=(",", ":"),
            sort_keys=True,
        )
        source_material = "|".join(
            (
                str(sequence),
                evidence_type,
                title,
                description,
                severity.value,
                source,
                canonical_metadata,
            )
        )
        digest = sha256(source_material.encode("utf-8")).hexdigest()
        return f"evidence:{digest[:EVIDENCE_DIGEST_LENGTH]}"
