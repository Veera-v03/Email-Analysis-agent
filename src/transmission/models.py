"""Standardized output object model (TransmissionAnalysis) and sub-DTOs matching Module 7 Specification."""

from __future__ import annotations

from datetime import datetime
from uuid import UUID, uuid4

from pydantic import Field

from src.common.models import BaseDTO


class EvaluatedHopDTO(BaseDTO):
    """Enriched transport hop evaluation object."""

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
    latency_seconds: float = Field(
        default=0.0, description="Transport delay from previous hop in seconds"
    )
    hop_classification: str = Field(
        default="EXTERNAL_UNTRUSTED",
        description="INTERNAL, EXTERNAL_TRUSTED, or EXTERNAL_UNTRUSTED",
    )
    cloud_provider: str | None = Field(
        default=None, description="Identified cloud provider (M365, GSuite, AWS)"
    )
    country_code: str | None = Field(
        default=None, description="GeoIP 2-letter country code"
    )
    asn: int | None = Field(default=None, description="Autonomous System Number")
    asn_org: str | None = Field(default=None, description="ISP / ASN Organization name")
    fcrdns_valid: bool | None = Field(
        default=None, description="Forward-Confirmed Reverse DNS validity"
    )


class SenderIdentityAnalysisDTO(BaseDTO):
    """Sender identity evaluation results."""

    from_address: str = Field(description="Normalized From header email address")
    from_domain: str = Field(description="Extracted From domain")
    from_display_name: str = Field(default="", description="From display name string")
    sender_address: str | None = Field(
        default=None, description="RFC 5322 Sender header address"
    )
    reply_to_address: str | None = Field(
        default=None, description="Reply-To header email address"
    )
    return_path_address: str | None = Field(
        default=None, description="Return-Path header address"
    )
    envelope_from_address: str | None = Field(
        default=None, description="RFC 5321 Envelope MAIL FROM address"
    )

    # Security Flags
    is_display_name_spoofed: bool = Field(
        default=False,
        description="Flag indicating Executive / Brand display name spoofing",
    )
    is_reply_to_mismatched: bool = Field(
        default=False, description="Flag indicating Reply-To != From mismatch"
    )
    is_reply_to_free_webmail: bool = Field(
        default=False,
        description="Flag indicating Reply-To target is free webmail (@gmail.com)",
    )
    is_return_path_mismatched: bool = Field(
        default=False, description="Flag indicating Return-Path != From mismatch"
    )
    is_envelope_from_mismatched: bool = Field(
        default=False, description="Flag indicating Envelope From != From mismatch"
    )


class HeaderAnomalyDTO(BaseDTO):
    """Individual header anomaly or threat signal detected."""

    anomaly_code: str = Field(
        description="Anomaly code string (e.g. ANOM_FAKE_RECEIVED_HEADER)"
    )
    description: str = Field(description="Human-readable anomaly explanation")
    severity: str = Field(description="Severity: LOW, MEDIUM, HIGH, CRITICAL")
    risk_score_impact: int = Field(
        default=0, description="Additive risk points contribution"
    )


class TransmissionAnalysis(BaseDTO):
    """Universal immutable output object representing complete header & transmission analysis."""

    # 1. Primary Identifiers
    analysis_id: UUID = Field(default_factory=uuid4, description="Unique analysis UUID")
    parsed_id: UUID = Field(description="Parent ParsedEmail UUID reference")
    raw_email_id: UUID = Field(description="Parent RawEmail UUID reference")
    account_id: UUID = Field(description="Associated EmailAccount UUID")
    tenant_id: UUID = Field(description="Associated Tenant UUID")
    message_id: str = Field(description="Provider message ID")
    internet_message_id: str = Field(description="RFC 5322 Message-ID header")

    # 2. Hop Chain & Timeline Evaluation
    evaluated_hops: list[EvaluatedHopDTO] = Field(
        default_factory=list, description="Enriched hop transport timeline"
    )
    total_transport_latency_seconds: float = Field(
        default=0.0, description="Cumulative latency across all hops"
    )
    originating_ip: str | None = Field(
        default=None, description="First external client IP address"
    )
    originating_country: str | None = Field(
        default=None, description="First external client country code"
    )
    originating_asn_org: str | None = Field(
        default=None, description="First external client ISP/ASN org"
    )

    # 3. Sender Identity Evaluation
    sender_identity: SenderIdentityAnalysisDTO = Field(
        description="Comprehensive sender identity evaluation"
    )

    # 4. Message Metadata & Headers Analysis
    message_id_domain: str | None = Field(
        default=None, description="Extracted domain from Message-ID header"
    )
    is_message_id_mismatched: bool = Field(
        default=False, description="Flag indicating Message-ID domain != From domain"
    )
    is_missing_message_id: bool = Field(
        default=False, description="Flag indicating missing RFC 5322 Message-ID"
    )
    is_thread_hijack_suspect: bool = Field(
        default=False,
        description="Flag indicating fake Re: prefix without parent thread",
    )
    is_mailing_list: bool = Field(
        default=False,
        description="Flag indicating List-Id / List-Unsubscribe bulk email",
    )
    is_auto_submitted: bool = Field(
        default=False, description="Flag indicating Auto-Submitted / OOF auto-reply"
    )
    is_bounce_notice: bool = Field(
        default=False, description="Flag indicating DSN / Non-Delivery Report"
    )

    # 5. Detected Anomalies & Scoring Metrics
    anomalies: list[HeaderAnomalyDTO] = Field(
        default_factory=list, description="Detected header & transmission anomalies"
    )
    header_integrity_score: float = Field(
        default=1.0, description="Normalized header integrity confidence (0.0 to 1.0)"
    )
    sender_authenticity_score: float = Field(
        default=1.0,
        description="Normalized sender authenticity confidence (0.0 to 1.0)",
    )
    analysis_time_ms: float = Field(
        default=0.0, description="Analysis execution time in milliseconds"
    )
