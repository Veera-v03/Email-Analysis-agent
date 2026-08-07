"""Threat Intelligence Models & Enterprise Attack Taxonomy schemas matching Module 9 Specification."""

from __future__ import annotations

from enum import StrEnum
from uuid import UUID, uuid4

from pydantic import Field

from src.common.models import BaseDTO
from src.security_intelligence.threat_intel.framework import ThreatIntelObservation


class ThreatCategory(StrEnum):
    """Enterprise Attack Taxonomy Threat Categories."""

    CREDENTIAL_THEFT = "CREDENTIAL_THEFT"
    BEC = "BEC"
    QRISHING = "QRISHING"
    BRAND_IMPERSONATION = "BRAND_IMPERSONATION"
    MALWARE = "MALWARE"
    C2 = "C2"
    RANSOMWARE = "RANSOMWARE"
    TYPOSQUATTING = "TYPOSQUATTING"
    LOOKALIKE_DOMAIN = "LOOKALIKE_DOMAIN"
    INVOICE_FRAUD = "INVOICE_FRAUD"
    SUSPICIOUS_INFRASTRUCTURE = "SUSPICIOUS_INFRASTRUCTURE"
    UNKNOWN = "UNKNOWN"


class ConfidenceScoreDTO(BaseDTO):
    """Multi-dimensional threat confidence score model."""

    confidence: float = Field(
        default=0.0, description="Consolidated confidence score (0.0 - 1.0)"
    )
    provider_count: int = Field(
        default=0, description="Total providers contributing reputation data"
    )
    evidence: list[str] = Field(
        default_factory=list, description="Extracted evidence lines"
    )
    explanation: str = Field(
        default="No malicious threat indicators detected",
        description="Human readable explanation",
    )


class IOCTargetDetailDTO(BaseDTO):
    """Details for one enriched Indicator of Compromise."""

    target: str = Field(description="Indicator value (IP, Domain, URL, Hash, Email)")
    target_type: str = Field(description="ip, domain, url, hash, email")
    is_malicious: bool = Field(
        default=False, description="Flag indicating malicious assessment"
    )
    confidence: ConfidenceScoreDTO = Field(
        description="Multi-dimensional confidence score model"
    )
    matched_feeds: list[str] = Field(
        default_factory=list, description="Providers flagging this indicator"
    )
    threat_category: str = Field(
        default="UNKNOWN", description="Attack taxonomy category"
    )
    observations: list[ThreatIntelObservation] = Field(
        default_factory=list, description="Detailed provider observations"
    )


class ThreatIntelEnrichmentResult(BaseDTO):
    """Universal immutable output object representing complete threat intelligence enrichment."""

    # 1. Primary Identifiers
    enrichment_id: UUID = Field(
        default_factory=uuid4, description="Unique enrichment UUID"
    )
    parsed_id: UUID = Field(description="Parent ParsedEmail UUID reference")
    transmission_id: UUID = Field(
        description="Parent TransmissionAnalysis UUID reference"
    )
    auth_verification_id: UUID = Field(
        description="Parent AuthenticationVerification UUID reference"
    )
    account_id: UUID = Field(description="Associated EmailAccount UUID")
    tenant_id: UUID = Field(description="Associated Tenant UUID")
    message_id: str = Field(description="Provider message ID")

    # 2. Extracted IOC & Graph Summaries
    total_iocs_harvested: int = Field(
        default=0, description="Total count of unique IOCs harvested"
    )
    harvested_iocs: dict[str, list[str]] = Field(
        default_factory=dict, description="Categorized harvested IOC lists"
    )
    graph_node_count: int = Field(
        default=0, description="Graph nodes in IOC relationship topology"
    )
    graph_edge_count: int = Field(
        default=0, description="Graph directional edges connecting IOC nodes"
    )

    # 3. Threat Intelligence Enrichment Results
    enriched_targets: list[IOCTargetDetailDTO] = Field(
        default_factory=list, description="Enriched IOC target details"
    )
    malicious_ioc_count: int = Field(
        default=0, description="Count of matched malicious IOCs"
    )
    overall_confidence: ConfidenceScoreDTO = Field(
        description="Aggregated multi-dimensional confidence score"
    )
    matched_feeds: list[str] = Field(
        default_factory=list, description="Names of all matched threat feeds"
    )
    threat_categories: list[str] = Field(
        default_factory=list, description="Unique threat categories detected"
    )

    # 4. Aggregated Security Metrics
    intel_risk_score_impact: int = Field(
        default=0, description="Additive risk points contribution (0-50)"
    )
    enrichment_time_ms: float = Field(
        default=0.0, description="Enrichment execution time in milliseconds"
    )
