"""Standardized output object model (ParsedEmail) and sub-DTOs matching Module 6 Specification."""

from __future__ import annotations

from datetime import UTC, datetime
from uuid import UUID, uuid4

from pydantic import Field

from src.common.models import BaseDTO


class HeaderAddressDTO(BaseDTO):
    """Parsed email address header structure."""

    name: str = Field(default="", description="Display name")
    address: str = Field(description="Normalized email address")


class ReceivedHopDTO(BaseDTO):
    """Parsed RFC 5322 Received header hop context."""

    hop_index: int = Field(
        description="Order index of transport hop (0 = edge receiver)"
    )
    from_server: str | None = Field(
        default=None, description="HELO/EHLO server hostname/IP"
    )
    by_server: str | None = Field(
        default=None, description="Receiving server hostname/IP"
    )
    client_ip: str | None = Field(
        default=None, description="Extracted client IP address"
    )
    timestamp: datetime | None = Field(default=None, description="Hop timestamp")
    protocol: str | None = Field(default=None, description="ESMTP/ESMTPSA protocol")


class ExtractedURLDTO(BaseDTO):
    """Extracted URL entity with security metadata."""

    url: str = Field(description="Complete target URL")
    scheme: str = Field(description="URL scheme: http, https, etc.")
    domain: str = Field(description="Extracted domain/FQDN")
    anchor_text: str | None = Field(
        default=None, description="HTML link text if applicable"
    )
    is_mismatched: bool = Field(
        default=False, description="Flag indicating display text != target URL"
    )
    is_shortened: bool = Field(
        default=False, description="Flag indicating known link shortener"
    )
    surrounding_context: str | None = Field(
        default=None, description="Snippet text context surrounding URL"
    )


class ExtractedAttachmentDTO(BaseDTO):
    """Extracted file attachment metadata and payload reference."""

    attachment_id: UUID = Field(
        default_factory=uuid4, description="Unique attachment UUID"
    )
    filename: str = Field(description="Sanitized attachment filename")
    declared_content_type: str = Field(
        description="Content-Type string declared in headers"
    )
    detected_mime_type: str = Field(description="Magic-bytes verified MIME type")
    size_bytes: int = Field(description="Attachment file size in bytes")
    sha256: str = Field(description="SHA-256 cryptographic digest")
    md5: str = Field(description="MD5 cryptographic digest")
    content_id: str | None = Field(
        default=None, description="Content-ID for inline images (CID)"
    )
    is_inline: bool = Field(
        default=False, description="Flag indicating inline disposition"
    )
    raw_data: bytes | None = Field(
        default=None, description="Binary payload if stored in RAM"
    )
    storage_uri: str | None = Field(
        default=None, description="S3/MinIO storage URI for binary payload"
    )


class ParsingDiagnosticDTO(BaseDTO):
    """Diagnostic warning or non-fatal anomaly recorded during parsing."""

    code: str = Field(description="Diagnostic error code string")
    message: str = Field(description="Detailed anomaly description")
    severity: str = Field(description="Severity: WARNING, ERROR, RECOVERED")
    location: str | None = Field(
        default=None, description="MIME part or header location"
    )


class ParsedEmail(BaseDTO):
    """Universal immutable data object representing a completely parsed email."""

    # 1. Primary Metadata & Identifiers
    parsed_id: UUID = Field(
        default_factory=uuid4, description="Unique UUID for parsed email object"
    )
    raw_email_id: UUID = Field(
        description="Foreign key UUID referencing RawEmail record"
    )
    account_id: UUID = Field(description="Associated EmailAccount UUID")
    tenant_id: UUID = Field(description="Tenant UUID owner")
    message_id: str = Field(description="Provider message ID")
    internet_message_id: str = Field(description="RFC 5322 Message-ID header")

    # 2. Envelope & Header Metadata
    sender: HeaderAddressDTO = Field(description="Extracted From header address")
    reply_to: HeaderAddressDTO | None = Field(
        default=None, description="Extracted Reply-To header address"
    )
    recipients_to: list[HeaderAddressDTO] = Field(
        default_factory=list, description="To header addresses"
    )
    recipients_cc: list[HeaderAddressDTO] = Field(
        default_factory=list, description="Cc header addresses"
    )
    recipients_bcc: list[HeaderAddressDTO] = Field(
        default_factory=list, description="Bcc header addresses"
    )
    subject: str = Field(default="", description="Decoded email subject string")
    date: datetime = Field(
        default_factory=lambda: datetime.now(UTC),
        description="RFC 5322 Date header timestamp",
    )
    received_hops: list[ReceivedHopDTO] = Field(
        default_factory=list, description="Transport hop chain"
    )
    raw_headers: dict[str, list[str]] = Field(
        default_factory=dict, description="Complete raw headers dictionary"
    )

    # 3. Body Content
    body_plain: str = Field(
        default="", description="Normalized plain text body payload"
    )
    body_html: str = Field(default="", description="Sanitized HTML body payload")
    body_html_plain: str = Field(
        default="", description="Plain text extracted from HTML body"
    )
    normalized_text: str = Field(
        default="",
        description="Consolidated, Unicode-normalized text payload for AI/NLP",
    )

    # 4. Extracted Entities
    urls: list[ExtractedURLDTO] = Field(
        default_factory=list, description="Extracted URLs"
    )
    attachments: list[ExtractedAttachmentDTO] = Field(
        default_factory=list, description="Extracted attachments"
    )
    inline_images: list[ExtractedAttachmentDTO] = Field(
        default_factory=list, description="Extracted inline images (CID)"
    )

    # 5. Security & Anomalies Pre-Check Flags
    has_zero_width_chars: bool = Field(
        default=False,
        description="Flag indicating hidden zero-width unicode characters",
    )
    has_homoglyphs: bool = Field(
        default=False, description="Flag indicating unicode homoglyph domain spoofing"
    )
    has_mismatched_urls: bool = Field(
        default=False, description="Flag indicating link text != target URL mismatch"
    )
    has_executable_attachments: bool = Field(
        default=False,
        description="Flag indicating dangerous file extensions/magic bytes",
    )

    # 6. Diagnostics & Execution Context
    parsing_time_ms: float = Field(
        default=0.0, description="Parsing duration in milliseconds"
    )
    diagnostics: list[ParsingDiagnosticDTO] = Field(
        default_factory=list, description="Parsing anomaly logs"
    )
