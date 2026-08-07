"""MIME Parsing event contract payloads matching SAS v1.1.0 and Module 6 Specification."""

from __future__ import annotations

from uuid import UUID

from pydantic import Field

from src.events.base_event import BaseEvent


class EmailParsedEvent(BaseEvent):
    """Event emitted when an email MIME stream is successfully parsed into a ParsedEmail object."""

    event_type: str = "scamon.prod.parsing.email.parsed.v1"
    parsed_id: UUID = Field(description="Unique ParsedEmail UUID")
    raw_email_id: UUID = Field(description="Associated RawEmail UUID")
    account_id: UUID = Field(description="Associated EmailAccount UUID")
    message_id: str = Field(description="Provider message ID")
    internet_message_id: str = Field(description="RFC 5322 Message-ID header")
    sender_address: str = Field(description="Sender email address")
    recipient_count: int = Field(default=0, description="Total count of recipients")
    attachment_count: int = Field(
        default=0, description="Count of extracted attachments"
    )
    url_count: int = Field(default=0, description="Count of extracted URLs")
    parsing_time_ms: float = Field(description="Parsing duration in milliseconds")


class EmailParsingFailedEvent(BaseEvent):
    """Event emitted when email parsing encounters a non-recoverable failure."""

    event_type: str = "scamon.prod.parsing.email.failed.v1"
    raw_email_id: UUID = Field(description="Associated RawEmail UUID")
    account_id: UUID = Field(description="Associated EmailAccount UUID")
    message_id: str = Field(description="Provider message ID")
    error_message: str = Field(description="Detailed error description")


class AttachmentExtractedEvent(BaseEvent):
    """Event emitted for every individual file attachment extracted during parsing."""

    event_type: str = "scamon.prod.parsing.attachment.extracted.v1"
    attachment_id: UUID = Field(description="Unique ExtractedAttachment UUID")
    parsed_id: UUID = Field(description="Parent ParsedEmail UUID")
    filename: str = Field(description="Sanitized attachment filename")
    detected_mime_type: str = Field(description="Magic-bytes verified MIME type")
    size_bytes: int = Field(description="Attachment file size in bytes")
    sha256: str = Field(description="SHA-256 cryptographic digest")
    is_inline: bool = Field(
        default=False, description="Flag indicating CID inline image"
    )
