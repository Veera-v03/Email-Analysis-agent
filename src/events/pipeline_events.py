"""Pipeline lifecycle security events matching SAS v1.1.0."""

from __future__ import annotations

from uuid import UUID

from pydantic import Field

from src.events.base_event import BaseEvent


class PipelineStartedEvent(BaseEvent):
    """Event emitted when end-to-end email analysis pipeline starts."""

    event_type: str = "scamon.prod.pipeline.started.v1"
    raw_email_id: UUID = Field(description="Parent RawEmail UUID reference")
    message_id: str = Field(description="Internal message identifier")


class PipelineCompletedEvent(BaseEvent):
    """Event emitted when end-to-end email analysis pipeline completes successfully."""

    event_type: str = "scamon.prod.pipeline.completed.v1"
    analysis_id: UUID = Field(description="Unique analysis UUID")
    message_id: str = Field(description="Internal message identifier")
    verdict: str = Field(description="Final threat verdict")
    risk_score: int = Field(description="Consolidated risk score (0-100)")
    total_time_ms: float = Field(description="Total execution duration in ms")
    sla_breached: bool = Field(
        default=False, description="Flag indicating if any SLA budget was breached"
    )


class PipelineFailedEvent(BaseEvent):
    """Event emitted when email analysis pipeline fails on an unrecoverable error."""

    event_type: str = "scamon.prod.pipeline.failed.v1"
    raw_email_id: UUID = Field(description="Parent RawEmail UUID reference")
    message_id: str = Field(description="Internal message identifier")
    failed_stage: str = Field(description="Name of the stage that caused failure")
    error_message: str = Field(description="Detailed error message")
