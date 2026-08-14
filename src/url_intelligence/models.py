"""URL Intelligence output models and DTO schemas matching Module 15 Specification."""

from __future__ import annotations

from uuid import UUID, uuid4

from pydantic import Field

from src.common.models import BaseDTO
from src.content_intelligence.models import MediaStatus


class URLRedirectHopDTO(BaseDTO):
    """Single hop within an expanded URL redirect chain."""

    hop_number: int = Field(description="Sequential hop number (1..5)")
    url: str = Field(description="URL of this hop")
    canonical_url: str = Field(description="RFC 3986 canonicalized URL")
    resolved_ip: str = Field(description="SSRF-validated target IP address")
    status_code: int = Field(description="HTTP status code (301, 302, 200, etc.)")
    headers: dict[str, str] = Field(
        default_factory=dict, description="Response headers"
    )
    is_ssrf_safe: bool = Field(
        default=True, description="Flag indicating hop passed SSRF validation"
    )


class URLRedirectChainDTO(BaseDTO):
    """Complete expanded HTTP redirect chain."""

    initial_url: str = Field(description="First input target URL")
    final_destination_url: str = Field(description="Final resolved destination URL")
    total_hops: int = Field(default=0, description="Total redirect hop count")
    is_loop_detected: bool = Field(
        default=False, description="Flag indicating redirect loop detected"
    )
    is_shortener_expanded: bool = Field(
        default=False, description="Flag indicating shortened URL expanded"
    )
    hops: list[URLRedirectHopDTO] = Field(
        default_factory=list, description="List of per-hop DTOs"
    )


class URLSandboxResultDTO(BaseDTO):
    """Playwright headless browser execution evidence."""

    sandbox_status: MediaStatus = Field(
        default=MediaStatus.SKIPPED, description="Playwright engine status"
    )
    final_page_title: str | None = Field(
        default=None, description="HTML document title"
    )
    captured_form_actions: list[str] = Field(
        default_factory=list, description="Form action URLs detected on page"
    )
    has_credential_inputs: bool = Field(
        default=False, description="Flag indicating password/login input fields"
    )
    script_execution_count: int = Field(
        default=0, description="Count of executed scripts"
    )
    screenshot_available: bool = Field(
        default=False, description="Flag indicating page screenshot was captured"
    )
    screenshot_reference: str | None = Field(
        default=None, description="Metadata reference path to screenshot"
    )


class URLAnalysisResult(BaseDTO):
    """Universal immutable output object representing complete URL and sandbox intelligence."""

    analysis_id: UUID = Field(default_factory=uuid4, description="Unique analysis UUID")
    parsed_id: UUID = Field(description="Parent ParsedEmail UUID reference")
    tenant_id: UUID = Field(description="Associated Tenant UUID")
    message_id: str = Field(description="Provider message ID")
    extracted_urls_count: int = Field(
        default=0, description="Total count of analyzed URLs"
    )
    has_mismatched_urls: bool = Field(
        default=False, description="Display text != target URL domain"
    )
    has_shortened_urls: bool = Field(
        default=False, description="Contains link shorteners"
    )
    ssrf_violation_detected: bool = Field(
        default=False, description="Target attempted private IP access"
    )
    redirect_chain: URLRedirectChainDTO = Field(description="Expanded redirect chain")
    sandbox_result: URLSandboxResultDTO = Field(description="Playwright sandbox result")
    threat_feeds_flagged: list[str] = Field(
        default_factory=list, description="Flagged threat intel feeds"
    )
    execution_time_ms: float = Field(
        default=0.0, description="URL intelligence execution duration in ms"
    )
