"""Risk Assessment models, configurable policy schemas, and RiskAssessment DTO matching Module 10 Specification."""

from __future__ import annotations

from typing import Any
from uuid import UUID, uuid4

from pydantic import Field

from src.common.constants import ActionTaken, Verdict
from src.common.models import BaseDTO


class RiskEvidenceDTO(BaseDTO):
    """Rich structured evidence model detailing one risk factor."""

    source_module: str = Field(
        description="parsing, transmission, authentication, threat_intel"
    )
    feature_name: str = Field(description="Name of identified feature or anomaly")
    applied_weight: int = Field(description="Risk points weight contributed")
    confidence: float = Field(
        default=1.0, description="Feature evidence confidence (0.0 - 1.0)"
    )
    explanation: str = Field(description="Human readable explanation text")


class ConfidenceScoreDetailsDTO(BaseDTO):
    """Detailed confidence fusion model."""

    overall_confidence: float = Field(
        default=1.0, description="Fused assessment confidence (0.0 - 1.0)"
    )
    feature_completeness: float = Field(
        default=1.0, description="Upstream module feature presence (0.0 - 1.0)"
    )
    evidence_quality: float = Field(
        default=1.0, description="Quality and weight of evidence (0.0 - 1.0)"
    )
    provider_agreement: float = Field(
        default=1.0, description="Agreement across threat intel providers (0.0 - 1.0)"
    )


class RiskPolicyConfig(BaseDTO):
    """External configurable risk policy weights and verdict threshold parameters."""

    # Dynamic Weight Points per Rule
    weight_display_name_spoof: int = 40
    weight_malicious_ioc: int = 35
    weight_dmarc_fail: int = 30
    weight_reply_to_mismatch: int = 25
    weight_thread_hijack: int = 25
    weight_spf_fail: int = 20
    weight_dkim_fail: int = 15
    weight_low_header_integrity: int = 15
    weight_free_webmail_reply_to: int = 15
    weight_return_path_mismatch: int = 10

    # Policy Action Thresholds (Risk Score Boundaries)
    threshold_clean_max: int = 29
    threshold_suspicious_max: int = 69
    threshold_malicious_quarantine_max: int = 89


class RiskFeatureVector(BaseDTO):
    """Normalized feature vector extracted across Modules 6-9."""

    features: dict[str, Any] = Field(
        default_factory=dict, description="Raw and normalized feature map"
    )


class RiskAssessment(BaseDTO):
    """Universal immutable output object representing complete enterprise risk assessment."""

    # 1. Primary Identifiers
    assessment_id: UUID = Field(
        default_factory=uuid4, description="Unique assessment UUID"
    )
    parsed_id: UUID = Field(description="Parent ParsedEmail UUID reference")
    transmission_id: UUID = Field(
        description="Parent TransmissionAnalysis UUID reference"
    )
    auth_verification_id: UUID = Field(
        description="Parent AuthenticationVerification UUID reference"
    )
    intel_enrichment_id: UUID = Field(
        description="Parent ThreatIntelEnrichmentResult UUID reference"
    )
    account_id: UUID = Field(description="Associated EmailAccount UUID")
    tenant_id: UUID = Field(description="Associated Tenant UUID")
    message_id: str = Field(description="Provider message ID")

    # 2. Risk Assessment Results
    risk_score: int = Field(ge=0, le=100, description="Consolidated risk score (0-100)")
    verdict: Verdict = Field(description="CLEAN, SUSPICIOUS, MALICIOUS")
    recommended_action: ActionTaken = Field(
        description="DELIVERED, BANNER_INJECTED, QUARANTINED, BLOCKED"
    )
    confidence_details: ConfidenceScoreDetailsDTO = Field(
        description="Detailed confidence fusion metrics"
    )

    # 3. Explainability & Rich Evidence
    risk_evidence: list[RiskEvidenceDTO] = Field(
        default_factory=list, description="List of structured risk evidence"
    )
    threat_categories: list[str] = Field(
        default_factory=list, description="Matched attack categories"
    )
    explainability_summary: str = Field(
        description="Human readable explainability summary"
    )

    # 4. MITRE ATT&CK & SOC Mitigations
    mitre_techniques: list[dict[str, str]] = Field(
        default_factory=list, description="Mapped MITRE ATT&CK techniques"
    )
    soc_recommendations: list[str] = Field(
        default_factory=list, description="Actionable SOC mitigation steps"
    )

    # 5. Metadata
    scoring_strategy: str = Field(
        default="DeterministicWeightedScoringStrategy",
        description="Scoring strategy used",
    )
    assessment_time_ms: float = Field(
        default=0.0, description="Assessment execution time in milliseconds"
    )
