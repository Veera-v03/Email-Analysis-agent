"""Header and Transmission Analysis event contract payloads matching SAS v1.1.0 and Module 7 Specification."""

from __future__ import annotations

from uuid import UUID

from pydantic import Field

from src.events.base_event import BaseEvent


class HeaderAnalysisCompletedEvent(BaseEvent):
    """Event emitted when header and transmission analysis completes for an email."""

    event_type: str = "scamon.prod.transmission.analysis.completed.v1"
    analysis_id: UUID = Field(description="Unique TransmissionAnalysis UUID")
    parsed_id: UUID = Field(description="Parent ParsedEmail UUID")
    raw_email_id: UUID = Field(description="Parent RawEmail UUID")
    account_id: UUID = Field(description="Associated EmailAccount UUID")
    message_id: str = Field(description="Provider message ID")
    originating_ip: str | None = Field(
        default=None, description="First external client IP address"
    )
    originating_country: str | None = Field(
        default=None, description="First external client country code"
    )
    is_display_name_spoofed: bool = Field(
        default=False, description="Flag indicating display name spoofing"
    )
    is_reply_to_mismatched: bool = Field(
        default=False, description="Flag indicating Reply-To mismatch"
    )
    anomaly_count: int = Field(
        default=0, description="Total count of detected header anomalies"
    )
    header_integrity_score: float = Field(
        default=1.0, description="Header integrity score (0.0 to 1.0)"
    )
    sender_authenticity_score: float = Field(
        default=1.0, description="Sender authenticity score (0.0 to 1.0)"
    )
    analysis_time_ms: float = Field(description="Analysis duration in milliseconds")


class HeaderAnomalyDetectedEvent(BaseEvent):
    """Event emitted when a high-risk header or transmission anomaly is detected."""

    event_type: str = "scamon.prod.transmission.anomaly.detected.v1"
    analysis_id: UUID = Field(description="Unique TransmissionAnalysis UUID")
    parsed_id: UUID = Field(description="Parent ParsedEmail UUID")
    anomaly_code: str = Field(description="Anomaly code string")
    description: str = Field(description="Detailed anomaly description")
    severity: str = Field(description="Severity level: LOW, MEDIUM, HIGH, CRITICAL")
    risk_score_impact: int = Field(default=0, description="Additive risk point impact")
