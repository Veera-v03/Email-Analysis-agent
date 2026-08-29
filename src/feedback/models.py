"""Domain models, enumerations, and immutable DTOs for Module 24 Analyst Feedback."""

from __future__ import annotations

from datetime import UTC, datetime
from enum import StrEnum
from uuid import UUID, uuid4

from pydantic import Field

from src.common.constants import ActionTaken, Verdict
from src.common.models import BaseDTO


class AnalystVerdictCorrection(StrEnum):
    """Authoritative analyst verdict classification."""

    CONFIRMED_MALICIOUS = "CONFIRMED_MALICIOUS"
    CONFIRMED_SUSPICIOUS = "CONFIRMED_SUSPICIOUS"
    CONFIRMED_CLEAN = "CONFIRMED_CLEAN"
    FALSE_POSITIVE = "FALSE_POSITIVE"
    FALSE_NEGATIVE = "FALSE_NEGATIVE"
    BENIGN_ANOMALY = "BENIGN_ANOMALY"
    NEEDS_ESCALATION = "NEEDS_ESCALATION"


class FeedbackReasonCategory(StrEnum):
    """Categorized justification for verdict correction."""

    LEGITIMATE_MARKETING = "LEGITIMATE_MARKETING"
    INTERNAL_COMMUNICATION = "INTERNAL_COMMUNICATION"
    MISCONFIGURED_SPF_DKIM = "MISCONFIGURED_SPF_DKIM"
    AUTHORIZED_EXTERNAL_VENDOR = "AUTHORIZED_EXTERNAL_VENDOR"
    FALSE_POSITIVE_KEYWORD = "FALSE_POSITIVE_KEYWORD"
    OBFUSCATED_MALICIOUS_LINK = "OBFUSCATED_MALICIOUS_LINK"
    QR_CODE_CREDENTIAL_PHISH = "QR_CODE_CREDENTIAL_PHISH"
    VIP_IMPERSONATION = "VIP_IMPERSONATION"
    OTHER = "OTHER"


class AnalystTrustLevel(StrEnum):
    """Analyst permission and weighting tier."""

    JUNIOR_ANALYST = "JUNIOR_ANALYST"
    SENIOR_ANALYST = "SENIOR_ANALYST"
    LEAD_SOC_ADMIN = "LEAD_SOC_ADMIN"


ANALYST_TRUST_WEIGHTS: dict[AnalystTrustLevel, float] = {
    AnalystTrustLevel.JUNIOR_ANALYST: 0.50,
    AnalystTrustLevel.SENIOR_ANALYST: 0.85,
    AnalystTrustLevel.LEAD_SOC_ADMIN: 1.00,
}


class AnalystFeedbackSubmissionDTO(BaseDTO):
    """Incoming feedback submission payload from authenticated SOC analyst."""

    incident_id: UUID = Field(description="Referenced Incident primary key UUID")
    message_id: str = Field(min_length=1, max_length=512, description="Email message identifier")
    corrected_verdict: AnalystVerdictCorrection = Field(
        description="Analyst corrected verdict classification"
    )
    reason_category: FeedbackReasonCategory = Field(
        description="Categorized reason for the verdict correction"
    )
    analyst_notes: str = Field(
        default="",
        max_length=2000,
        description="Analyst narrative notes explaining the justification (max 2000 chars)",
    )
    override_remediation: bool = Field(
        default=False,
        description="If True, dispatches rollback / release remediation action",
    )
    evidence_tags: list[str] = Field(
        default_factory=list,
        description="Specific feature keys highlighted (e.g. 'dmarc_result', 'urgency_score')",
    )


class AnalystFeedbackRecordDTO(BaseDTO):
    """Immutable audit record of accepted analyst feedback."""

    feedback_id: UUID = Field(
        default_factory=uuid4,
        description="Unique feedback audit record identifier",
    )
    tenant_id: UUID = Field(description="Associated enterprise tenant UUID")
    account_id: UUID = Field(description="Associated mailbox account UUID")
    incident_id: UUID = Field(description="Target Incident UUID reference")
    message_id: str = Field(min_length=1, max_length=512, description="Email message identifier")

    original_risk_score: int = Field(
        ge=0,
        le=100,
        description="Original system calculated risk score (0-100)",
    )
    original_calibrated_prob: float = Field(
        ge=0.0,
        le=1.0,
        description="Original calibrated threat probability (0.0-1.0)",
    )
    original_verdict: Verdict = Field(description="Original system verdict")
    original_action: ActionTaken = Field(description="Original system remediation action")

    corrected_verdict: AnalystVerdictCorrection = Field(
        description="Analyst corrected verdict classification"
    )
    reason_category: FeedbackReasonCategory = Field(
        description="Categorized reason for the verdict correction"
    )

    analyst_id: str = Field(min_length=1, description="Authenticated analyst user ID / email")
    analyst_trust_level: AnalystTrustLevel = Field(
        description="Analyst trust tier determining convergence weight"
    )
    analyst_notes: str = Field(
        default="",
        max_length=2000,
        description="Analyst narrative notes",
    )

    convergence_applied: bool = Field(
        default=False,
        description="Flag indicating if memory convergence has been executed",
    )
    convergence_weight: float = Field(
        default=0.0,
        ge=0.0,
        le=1.0,
        description="Applied convergence weight factor (0.0-1.0)",
    )

    created_at: datetime = Field(
        default_factory=lambda: datetime.now(UTC),
        description="Feedback submission UTC timestamp",
    )


class AuthenticatedAnalystDTO(BaseDTO):
    """Verified analyst caller context extracted from authentication claims."""

    analyst_id: str = Field(description="Unique analyst identifier / subject ID")
    tenant_id: UUID = Field(description="Tenant UUID boundary")
    role: str = Field(description="Analyst RBAC role (e.g. ANALYST, ADMIN, SUPER_ADMIN)")
    email: str = Field(default="", description="Analyst email address")
    trust_level: AnalystTrustLevel | None = Field(
        default=None,
        description="Optional explicitly assigned trust level override",
    )


class AnalystFeedbackResponseDTO(BaseDTO):
    """Standard API response payload returned upon successful feedback acceptance."""

    status: str = Field(default="ACCEPTED", description="Feedback acceptance status")
    feedback_id: UUID = Field(description="Unique generated feedback audit record UUID")
    incident_id: UUID = Field(description="Target Incident UUID reference")
    message: str = Field(
        default="Analyst feedback accepted and queued for convergence",
        description="User-friendly status confirmation message",
    )


class ConvergenceResultDTO(BaseDTO):
    """Result of processing a feedback convergence update for tenant memory."""

    feedback_id: UUID = Field(description="Referenced feedback record UUID")
    tenant_id: UUID = Field(description="Target tenant UUID")
    entity_key: str = Field(description="Target sender/domain/IOC identifier")
    prior_score: float = Field(ge=0.0, le=1.0, description="Reputation score prior to convergence")
    posterior_score: float = Field(ge=0.0, le=1.0, description="Reputation score after convergence")
    delta: float = Field(ge=-0.20, le=0.20, description="Bounded delta applied to score")
    applied: bool = Field(default=True, description="True if update was applied, False if idempotent duplicate")
    reason: str = Field(default="CONVERGENCE_APPLIED", description="Status code or rationale")
    timestamp: datetime = Field(
        default_factory=lambda: datetime.now(UTC),
        description="Convergence execution timestamp",
    )


class ConvergenceRollbackResultDTO(BaseDTO):
    """Result of administratively rolling back a prior convergence update."""

    feedback_id: UUID = Field(description="Target feedback record UUID rolled back")
    tenant_id: UUID = Field(description="Target tenant UUID")
    entity_key: str = Field(description="Target sender/domain/IOC identifier")
    restored_score: float = Field(ge=0.0, le=1.0, description="Reputation score restored after rollback")
    rolled_back_by: str = Field(description="Admin user ID who authorized the rollback")
    message: str = Field(
        default="Convergence update successfully rolled back",
        description="Confirmation message",
    )
    timestamp: datetime = Field(
        default_factory=lambda: datetime.now(UTC),
        description="Rollback execution timestamp",
    )


class RecommendationDirection(StrEnum):
    """Directional adjustment suggested for tenant risk sensitivity."""

    INCREASE_SENSITIVITY = "INCREASE_SENSITIVITY"
    DECREASE_SENSITIVITY = "DECREASE_SENSITIVITY"
    MAINTAIN = "MAINTAIN"
    INSUFFICIENT_DATA = "INSUFFICIENT_DATA"


class RecommendationStatus(StrEnum):
    """Lifecycle status of an advisory sensitivity recommendation."""

    PENDING_REVIEW = "PENDING_REVIEW"
    APPLIED = "APPLIED"
    REJECTED = "REJECTED"
    SUPERSEDED = "SUPERSEDED"


class RollingWindowAnalyticsDTO(BaseDTO):
    """Statistical summary of feedback distribution and error rates for a rolling window."""

    tenant_id: UUID = Field(description="Tenant UUID boundary")
    window_days: int = Field(ge=1, le=365, description="Rolling window duration in days")
    window_start: datetime = Field(description="Window start UTC timestamp")
    window_end: datetime = Field(description="Window end UTC timestamp")
    sample_count: int = Field(ge=0, description="Total feedback samples in window")

    false_positive_count: int = Field(default=0, ge=0)
    false_negative_count: int = Field(default=0, ge=0)
    confirmed_clean_count: int = Field(default=0, ge=0)
    confirmed_malicious_count: int = Field(default=0, ge=0)
    confirmed_suspicious_count: int = Field(default=0, ge=0)
    benign_anomaly_count: int = Field(default=0, ge=0)
    needs_escalation_count: int = Field(default=0, ge=0)

    false_positive_rate: float | None = Field(
        default=None,
        ge=0.0,
        le=1.0,
        description="FPR = FP / (FP + TN), or None if denominator is 0",
    )
    false_negative_rate: float | None = Field(
        default=None,
        ge=0.0,
        le=1.0,
        description="FNR = FN / (FN + TP), or None if denominator is 0",
    )
    error_distribution: dict[str, int] = Field(
        default_factory=dict,
        description="Count breakdown per verdict correction category",
    )


class SensitivityRecommendationDTO(BaseDTO):
    """Advisory recommendation for adjusting tenant risk sensitivity policy."""

    recommendation_id: UUID = Field(
        default_factory=uuid4,
        description="Unique recommendation UUID identifier",
    )
    tenant_id: UUID = Field(description="Target enterprise tenant UUID")
    generated_at: datetime = Field(
        default_factory=lambda: datetime.now(UTC),
        description="Generation UTC timestamp",
    )
    window_days: int = Field(default=30, ge=1, le=365)
    sample_count: int = Field(ge=0)

    false_positive_rate: float | None = None
    false_negative_rate: float | None = None

    current_sensitivity: str = Field(description="Current active sensitivity setting (e.g. BALANCED)")
    recommended_sensitivity: str = Field(description="Suggested sensitivity setting (e.g. PERMISSIVE)")
    direction: RecommendationDirection = Field(description="Directional adjustment")
    status: RecommendationStatus = Field(
        default=RecommendationStatus.PENDING_REVIEW,
        description="Lifecycle status",
    )

    reason: str = Field(description="Concise rationale code")
    explanation: str = Field(max_length=2000, description="Explainable human-readable justification narrative")

    applied_by: str | None = None
    applied_at: datetime | None = None


class ApplyRecommendationResponseDTO(BaseDTO):
    """Confirmation payload returned when an administrator applies a recommendation."""

    recommendation_id: UUID = Field(description="Applied recommendation UUID")
    tenant_id: UUID = Field(description="Tenant UUID boundary")
    previous_sensitivity: str = Field(description="Sensitivity before application")
    new_sensitivity: str = Field(description="Updated active sensitivity setting")
    applied_by: str = Field(description="Admin user ID who approved and applied the change")
    applied_at: datetime = Field(
        default_factory=lambda: datetime.now(UTC),
        description="Application UTC timestamp",
    )
    message: str = Field(
        default="Recommendation successfully applied to tenant profile",
        description="Confirmation message",
    )
