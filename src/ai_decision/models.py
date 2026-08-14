"""AI Decision Plan models, provenance schemas, and DecisionPlan DTO matching Module 11 Specification."""

from __future__ import annotations

from uuid import UUID, uuid4

from pydantic import Field

from src.common.models import BaseDTO


class ExplainabilityProvenanceDTO(BaseDTO):
    """Maps an AI explanation statement back to supporting upstream evidence."""

    explanation_sentence: str = Field(description="Generated explanation statement")
    source_module: str = Field(
        description="parsing, transmission, authentication, threat_intel, risk"
    )
    supporting_feature: str = Field(
        description="Feature name providing empirical evidence"
    )


class PromptMetadataDTO(BaseDTO):
    """Prompt and template versioning metadata."""

    prompt_version: str = Field(
        default="1.0.0", description="Version of prompt template"
    )
    template_version: str = Field(
        default="1.0.0", description="Version of formatting template"
    )
    provider_version: str = Field(
        default="gemini-1.5-flash", description="LLM model version"
    )


class DecisionPlan(BaseDTO):
    """Universal immutable output object representing complete AI Decision Plan & Explainability."""

    # 1. Primary Identifiers & Metadata
    plan_id: UUID = Field(
        default_factory=uuid4, description="Unique decision plan UUID"
    )
    assessment_id: UUID = Field(description="Parent RiskAssessment UUID reference")
    tenant_id: UUID = Field(description="Associated Tenant UUID")
    message_id: str = Field(description="Provider message ID")
    schema_version: str = Field(
        default="1.0.0", description="Schema version identifier"
    )

    # 2. Executive & Technical Summaries
    executive_summary: str = Field(
        description="Non-technical executive summary for SOC managers and CISO"
    )
    technical_summary: str = Field(
        description="Technical summary of indicators, headers, and authentication"
    )
    analyst_explanation: str = Field(
        description="Deep-dive explanation for tier-2 security analysts"
    )
    attack_summary: str = Field(
        description="Summary of identified attack vector and tactics"
    )

    # 3. Provenance, MITRE & Impact
    provenance_mappings: list[ExplainabilityProvenanceDTO] = Field(
        default_factory=list, description="Provenance evidence links"
    )
    mitre_techniques: list[dict[str, str]] = Field(
        default_factory=list, description="Mapped MITRE ATT&CK techniques"
    )
    business_impact: str = Field(
        description="Estimated business and operational impact"
    )

    # 4. Actions & Automation Candidates
    recommended_actions: list[str] = Field(
        default_factory=list, description="Ordered remediation actions"
    )
    automation_candidates: list[str] = Field(
        default_factory=list, description="SOAR automation playbooks to trigger"
    )

    # 5. Dual Confidence & Limitations
    risk_confidence: float = Field(
        ge=0.0, le=1.0, description="Risk confidence from Module 10"
    )
    ai_decision_confidence: float = Field(
        ge=0.0, le=1.0, description="AI decision confidence from Module 11"
    )
    limitations: list[str] = Field(
        default_factory=list, description="Analysis scope limitations or assumptions"
    )

    # 6. Metadata
    prompt_metadata: PromptMetadataDTO = Field(
        default_factory=PromptMetadataDTO, description="Prompt versioning metadata"
    )
    generation_time_ms: float = Field(
        default=0.0, description="Execution time in milliseconds"
    )
