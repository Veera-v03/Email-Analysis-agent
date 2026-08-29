"""Feedback and analyst verdict correction event contracts matching ScamON Event Architecture."""

from __future__ import annotations

from uuid import UUID

from pydantic import Field

from src.events.base_event import BaseEvent


class AnalystVerdictSubmittedEvent(BaseEvent):
    """Event emitted when analyst feedback is validated and recorded."""

    event_type: str = "scamon.prod.feedback.submitted.v1"
    feedback_id: UUID = Field(description="Referenced feedback record UUID")
    incident_id: UUID = Field(description="Referenced incident UUID")
    message_id: str = Field(description="Email message identifier")
    original_verdict: str = Field(description="Original system verdict")
    corrected_verdict: str = Field(description="Analyst corrected verdict")
    reason_category: str = Field(description="Reason category justification")
    analyst_id: str = Field(description="Analyst identifier")
    analyst_trust_level: str = Field(description="Analyst trust tier")


class FalsePositiveConfirmedEvent(BaseEvent):
    """Event emitted when a False Positive is confirmed to trigger trust convergence."""

    event_type: str = "scamon.prod.feedback.false_positive.v1"
    feedback_id: UUID = Field(description="Referenced feedback record UUID")
    incident_id: UUID = Field(description="Referenced incident UUID")
    sender_domain: str = Field(description="Sender domain for trust convergence")
    sender_address: str = Field(description="Sender email address")
    evidence_tags: list[str] = Field(
        default_factory=list,
        description="Associated evidence tags",
    )


class FalseNegativeConfirmedEvent(BaseEvent):
    """Event emitted when a False Negative is confirmed to flag malicious infrastructure."""

    event_type: str = "scamon.prod.feedback.false_negative.v1"
    feedback_id: UUID = Field(description="Referenced feedback record UUID")
    incident_id: UUID = Field(description="Referenced incident UUID")
    sender_domain: str = Field(description="Sender domain for reputation penalty")
    malicious_iocs: list[str] = Field(
        default_factory=list,
        description="Associated malicious IOC indicators",
    )
