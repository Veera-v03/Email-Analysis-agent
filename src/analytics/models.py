"""DTO definitions for Module 19 Enterprise Threat Analytics and Reporting."""

from __future__ import annotations

from typing import Any
from uuid import UUID, uuid4

from pydantic import ConfigDict, Field

from src.common.models import BaseDTO


class TenantAnalyticsRequestDTO(BaseDTO):
    """Input DTO requesting tenant threat analytics over a specified time window."""

    model_config = ConfigDict(extra="forbid", strict=True, frozen=False)

    tenant_id: UUID = Field(description="Target Tenant UUID")
    time_window_hours: int = Field(
        default=24, ge=1, le=720, description="Query time window in hours (1 to 720)"
    )
    include_remediation_summary: bool = Field(
        default=True, description="Flag to aggregate SOC remediation metrics"
    )


class TenantAnalyticsSummaryDTO(BaseDTO):
    """Universal output object representing tenant threat analytics and security posture."""

    model_config = ConfigDict(extra="forbid", strict=True, frozen=False)

    tenant_id: UUID = Field(description="Target Tenant UUID")
    time_window_hours: int = Field(description="Evaluation time window in hours")
    total_emails_analyzed: int = Field(
        default=0, ge=0, description="Total email investigations"
    )
    total_threats_detected: int = Field(
        default=0, ge=0, description="Total malicious or suspicious threats"
    )
    threat_breakdown_by_verdict: dict[str, int] = Field(
        default_factory=dict,
        description="Counts by verdict (BENIGN, SUSPICIOUS, MALICIOUS)",
    )
    remediation_breakdown_by_action: dict[str, int] = Field(
        default_factory=dict,
        description="Counts by approved remediation action (QUARANTINED, BLOCKED, etc.)",
    )
    top_threat_senders: list[dict[str, Any]] = Field(
        default_factory=list,
        description="Top sender addresses associated with threat verdicts",
    )
    average_investigation_latency_ms: float = Field(
        default=0.0, ge=0.0, description="Average pipeline investigation duration in ms"
    )
    generated_at: str = Field(description="ISO 8601 creation timestamp")


class ExecutiveReportDTO(BaseDTO):
    """Exportable executive threat and compliance report payload."""

    model_config = ConfigDict(extra="forbid", strict=True, frozen=False)

    report_id: UUID = Field(default_factory=uuid4, description="Unique report run UUID")
    tenant_id: UUID = Field(description="Target Tenant UUID")
    title: str = Field(
        default="Executive Threat & Security Posture Report",
        description="Report title string",
    )
    summary: TenantAnalyticsSummaryDTO = Field(
        description="Underlying analytics summary payload"
    )
    compliance_status: str = Field(
        default="COMPLIANT", description="COMPLIANT or ATTENTION_REQUIRED"
    )
    report_format: str = Field(
        default="JSON", description="Export format: JSON, CSV, SUMMARY_TEXT"
    )
    report_data: str = Field(description="Serialized report body text")
