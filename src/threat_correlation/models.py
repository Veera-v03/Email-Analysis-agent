"""Threat Correlation output models and DTO schemas matching Module 16 Specification."""

from __future__ import annotations

from typing import Any
from uuid import UUID, uuid4

from pydantic import Field

from src.common.models import BaseDTO


class IOCRelationshipGraphDTO(BaseDTO):
    """Adjacency list graph representing cross-indicator relationships (Sender -> Domain -> IP -> URL)."""

    nodes: list[str] = Field(
        default_factory=list, description="Unique indicator node identifiers"
    )
    edges: dict[str, list[str]] = Field(
        default_factory=dict,
        description="Adjacency list mapping node -> list[connected_nodes]",
    )
    total_nodes: int = Field(default=0, description="Total node count in graph")
    total_edges: int = Field(default=0, description="Total edge count in graph")


class ThreatCorrelationResult(BaseDTO):
    """Universal immutable output object representing complete threat correlation and campaign intelligence."""

    correlation_id: UUID = Field(
        default_factory=uuid4, description="Unique correlation run UUID"
    )
    parsed_id: UUID = Field(description="Parent ParsedEmail UUID reference")
    tenant_id: UUID = Field(description="Associated Tenant UUID")
    message_id: str = Field(description="Provider message ID")

    # Relationship Graph & Correlated IOCs
    related_iocs: list[str] = Field(
        default_factory=list, description="Extracted and correlated IOC strings"
    )
    relationship_graph: IOCRelationshipGraphDTO = Field(
        description="Cross-indicator adjacency graph"
    )

    # Campaign Clustering
    campaign_detected: bool = Field(
        default=False, description="Flag indicating multi-incident coordinated campaign"
    )
    campaign_id: str | None = Field(
        default=None, description="Correlated campaign cluster identifier"
    )
    campaign_score: float = Field(
        default=0.0,
        ge=0.0,
        le=10.0,
        description="Campaign confidence score (0.0 to 10.0)",
    )
    matched_campaign_indicators: list[str] = Field(
        default_factory=list,
        description="Trigger reasons: sender_match, template_subject_match, infrastructure_match",
    )
    historical_matches: list[dict[str, Any]] = Field(
        default_factory=list, description="Matched historical investigation records"
    )

    # Threat Taxonomy & MITRE ATT&CK Mappings
    threat_categories: list[str] = Field(
        default_factory=list, description="Aggregated enterprise threat categories"
    )
    mitre_techniques: list[dict[str, str]] = Field(
        default_factory=list,
        description="Correlated MITRE ATT&CK techniques (T1566, T1566.002, T1204.002, etc.)",
    )

    # Provenance & Telemetry
    correlation_confidence: float = Field(
        default=0.0, ge=0.0, le=1.0, description="Overall correlation confidence score"
    )
    evidence_summary: list[str] = Field(
        default_factory=list, description="Human-readable provenance evidence snippets"
    )
    execution_time_ms: float = Field(
        default=0.0, description="Correlation execution duration in ms"
    )
