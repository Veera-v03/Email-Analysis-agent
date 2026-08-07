"""Standardized output object model (AuthenticationVerification) and sub-DTOs matching Module 8 Specification."""

from __future__ import annotations

from uuid import UUID, uuid4

from pydantic import Field

from src.common.models import BaseDTO


class SPFResultDTO(BaseDTO):
    """Detailed SPF evaluation result."""

    result: str = Field(
        description="PASS, FAIL, SOFTFAIL, NEUTRAL, NONE, PERMERROR, TEMPERROR"
    )
    domain: str = Field(description="Evaluated SPF domain")
    client_ip: str | None = Field(
        default=None, description="Evaluated client IP address"
    )
    spf_record: str | None = Field(
        default=None, description="Retrieved v=spf1 DNS TXT record"
    )
    dns_lookup_count: int = Field(
        default=0, description="Count of DNS lookups performed (max 10)"
    )


class DKIMSignatureResultDTO(BaseDTO):
    """Individual DKIM signature verification result."""

    selector: str = Field(description="DKIM selector (s=)")
    domain: str = Field(description="DKIM signing domain (d=)")
    result: str = Field(description="PASS, FAIL, NONE, PERMERROR, TEMPERROR")
    canonicalization: str = Field(
        default="relaxed/relaxed", description="Header/Body canonicalization"
    )
    algorithm: str = Field(default="rsa-sha256", description="Signature algorithm (a=)")
    error_message: str | None = Field(
        default=None, description="Verification error details if failed"
    )


class DMARCResultDTO(BaseDTO):
    """Comprehensive DMARC policy & alignment evaluation result."""

    result: str = Field(description="PASS, FAIL, NONE")
    domain: str = Field(description="Evaluated From header domain")
    policy: str = Field(
        default="none", description="DMARC policy: none, quarantine, reject"
    )
    subdomain_policy: str | None = Field(
        default=None, description="DMARC subdomain policy (sp=)"
    )
    percentage: int = Field(
        default=100, description="Policy enforcement percentage (pct=)"
    )
    spf_aligned: bool = Field(
        default=False, description="Flag indicating SPF domain alignment"
    )
    dkim_aligned: bool = Field(
        default=False, description="Flag indicating DKIM domain alignment"
    )
    dmarc_record: str | None = Field(
        default=None, description="Retrieved _dmarc DNS TXT record"
    )


class ARCChainResultDTO(BaseDTO):
    """ARC chain validation result."""

    chain_valid: bool = Field(
        default=False,
        description="Flag indicating overall ARC chain validity (cv=pass)",
    )
    instance_count: int = Field(
        default=0, description="Number of ARC instances in chain (i=1..N)"
    )
    latest_result: str = Field(default="none", description="Latest ARC-Seal cv result")


class AuthenticationVerification(BaseDTO):
    """Universal immutable output object representing complete email authentication verification."""

    # 1. Primary Identifiers
    verification_id: UUID = Field(
        default_factory=uuid4, description="Unique verification UUID"
    )
    parsed_id: UUID = Field(description="Parent ParsedEmail UUID reference")
    transmission_id: UUID = Field(
        description="Parent TransmissionAnalysis UUID reference"
    )
    account_id: UUID = Field(description="Associated EmailAccount UUID")
    tenant_id: UUID = Field(description="Associated Tenant UUID")
    message_id: str = Field(description="Provider message ID")
    internet_message_id: str = Field(description="RFC 5322 Message-ID header")

    # 2. Authentication Evaluation Results
    spf: SPFResultDTO = Field(description="SPF evaluation details")
    dkim_signatures: list[DKIMSignatureResultDTO] = Field(
        default_factory=list, description="Verified DKIM signatures"
    )
    dkim_overall_result: str = Field(
        default="NONE", description="Consolidated DKIM result: PASS, FAIL, NONE"
    )
    dmarc: DMARCResultDTO = Field(
        description="DMARC policy & alignment evaluation details"
    )
    arc: ARCChainResultDTO = Field(
        default_factory=ARCChainResultDTO, description="ARC chain validation details"
    )

    # 3. Aggregated Security Metrics
    auth_pass_summary: bool = Field(
        default=False, description="True if DMARC PASS or both SPF+DKIM PASS"
    )
    auth_risk_score_impact: int = Field(
        default=0, description="Additive risk points contribution (0-50)"
    )
    verification_time_ms: float = Field(
        default=0.0, description="Verification execution time in milliseconds"
    )
