"""Multimodal threat signal fusion models and DTO contracts (Module 23)."""

from __future__ import annotations

from datetime import UTC, datetime
from enum import StrEnum
from typing import Any
from uuid import UUID

from pydantic import Field

from src.common.models import BaseDTO


class SignalDomain(StrEnum):
    """Supported intelligence domain categories."""

    AUTHENTICATION = "authentication"
    TRANSMISSION = "transmission"
    THREAT_INTEL = "threat_intel"
    CONTENT = "content_intelligence"
    MEDIA = "media_intelligence"
    URL = "url_intelligence"
    CORRELATION = "threat_correlation"


class EvidenceStatus(StrEnum):
    """Explicit evaluation status tracking provenance of individual threat signals."""

    EVALUATED_POSITIVE = "EVALUATED_POSITIVE"
    EVALUATED_NEGATIVE = "EVALUATED_NEGATIVE"
    SKIPPED = "SKIPPED"
    UNAVAILABLE = "UNAVAILABLE"
    ERROR = "ERROR"


class NormalizedSignalDTO(BaseDTO):
    """Normalized, provenance-tracked threat indicator signal."""

    domain: SignalDomain = Field(description="Originating intelligence domain")
    signal_name: str = Field(description="Unique feature or indicator identifier")
    raw_value: Any = Field(description="Sanitized raw value from upstream extractor")
    normalized_score: float = Field(
        default=0.0,
        ge=0.0,
        le=1.0,
        description="Continuous threat severity score (0.0=Benign, 1.0=Critical)",
    )
    confidence: float = Field(
        default=1.0,
        ge=0.0,
        le=1.0,
        description="Feature or provider confidence rating (0.0 to 1.0)",
    )
    weight: float = Field(
        default=1.0,
        ge=0.0,
        description="Relative domain weight factor for composite scoring",
    )
    status: EvidenceStatus = Field(
        default=EvidenceStatus.EVALUATED_POSITIVE,
        description="Explicit provenance status",
    )
    explanation: str = Field(
        default="", description="Human-readable justification or context"
    )
    extracted_at: datetime = Field(
        default_factory=lambda: datetime.now(UTC),
        description="UTC timestamp of feature normalization",
    )


class MultimodalFeatureVectorDTO(BaseDTO):
    """Unified multimodal feature container holding normalized signals across all 7 intelligence domains."""

    tenant_id: UUID = Field(description="Enterprise tenant UUID ensuring isolation")
    message_id: str = Field(description="Provider message identifier")
    domain_subscores: dict[str, float] = Field(
        default_factory=dict,
        description="Normalized domain subscores [0.0, 1.0] keyed by SignalDomain string",
    )
    signals: list[NormalizedSignalDTO] = Field(
        default_factory=list, description="List of all normalized signal DTOs"
    )
    completeness_ratio: float = Field(
        default=1.0,
        ge=0.0,
        le=1.0,
        description="Ratio of successfully evaluated signals over total potential signals",
    )
    total_evaluated_signals: int = Field(
        default=0,
        ge=0,
        description="Total signals with status EVALUATED_POSITIVE or EVALUATED_NEGATIVE",
    )
