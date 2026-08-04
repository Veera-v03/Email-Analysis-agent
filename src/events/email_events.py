"""Email pipeline event payload contracts matching SAS v1.1.0."""

from __future__ import annotations

from datetime import UTC, datetime

from pydantic import Field

from src.events.base_event import BaseEvent


class EmailIngestedEvent(BaseEvent):
    """Event emitted when a raw email is ingested and saved to S3/MinIO."""

    event_type: str = "scamon.prod.email.ingested.v1"
    message_id: str = Field(description="Internal unique message identifier")
    internet_message_id: str = Field(description="RFC 5322 Message-ID header value")
    ingestion_source: str = Field(
        description="Ingestion vector: GRAPH_API, WORKSPACE_API, or SMTP_MX"
    )
    raw_eml_s3_uri: str = Field(description="Storage S3 URI for raw EML payload")
    received_at: datetime = Field(
        default_factory=lambda: datetime.now(UTC),
        description="Original email receipt timestamp",
    )


class EmailParsedEvent(BaseEvent):
    """Event emitted when an email MIME tree has been parsed and decomposed."""

    event_type: str = "scamon.prod.email.parsed.v1"
    message_id: str = Field(description="Internal message identifier")
    sender_address: str = Field(description="Extracted sender email address")
    recipient_addresses: list[str] = Field(
        default_factory=list, description="Extracted recipient list"
    )
    subject: str = Field(default="", description="Email subject string")
    has_html_body: bool = Field(default=False, description="Flag indicating HTML body")
    attachment_count: int = Field(default=0, description="Extracted attachment count")
    extracted_urls: list[str] = Field(
        default_factory=list, description="Extracted body URLs"
    )


class EmailRenderedEvent(BaseEvent):
    """Event emitted when Playwright renders screenshot for an email link."""

    event_type: str = "scamon.prod.email.rendered.v1"
    message_id: str = Field(description="Internal message identifier")
    target_url: str = Field(description="Target URL rendered")
    screenshot_s3_uri: str = Field(description="S3 URI for captured page screenshot")
    dom_title: str | None = Field(
        default=None, description="DOM head title element text"
    )
