"""Orchestrator context, generic StageResult[T], and EmailAnalysisResult schemas matching Module 12 Specification."""

from __future__ import annotations

from datetime import UTC, datetime
from enum import StrEnum
from typing import Any, Generic, TypeVar
from uuid import UUID, uuid4

from pydantic import Field

from src.ai_decision.models import DecisionPlan
from src.authentication.models import AuthenticationVerification
from src.common.models import BaseDTO
from src.parsing.models import ParsedEmail
from src.risk.models import RiskAssessment
from src.threat_intel.models import ThreatIntelEnrichmentResult
from src.transmission.models import TransmissionAnalysis

T = TypeVar("T")


class StageStatus(StrEnum):
    """Pipeline stage execution status."""

    SUCCESS = "SUCCESS"
    DEGRADED = "DEGRADED"
    FAILED = "FAILED"


class StageClassification(StrEnum):
    """Failure classification policy per stage."""

    CRITICAL = "CRITICAL"  # Pipeline halts on failure
    OPTIONAL = "OPTIONAL"  # Pipeline continues in degraded mode on failure


class PipelineContext(BaseDTO):
    """Shared pipeline context passed across every stage execution."""

    analysis_id: UUID = Field(default_factory=uuid4, description="Unique analysis UUID")
    tenant_id: UUID = Field(description="Associated Tenant UUID")
    correlation_id: str = Field(
        default_factory=lambda: str(uuid4()), description="Cross-system correlation ID"
    )
    trace_id: str = Field(
        default_factory=lambda: str(uuid4()), description="Distributed tracing ID"
    )
    execution_start_time: datetime = Field(
        default_factory=lambda: datetime.now(UTC),
        description="Pipeline start timestamp",
    )
    retry_count: int = Field(default=0, description="Stage retry counter")
    metadata: dict[str, Any] = Field(
        default_factory=dict, description="Arbitrary context metadata"
    )


class StageResult(BaseDTO, Generic[T]):
    """Generic wrapper for individual stage execution results."""

    status: StageStatus = Field(description="SUCCESS, DEGRADED, FAILED")
    execution_time_ms: float = Field(
        default=0.0, description="Stage duration in milliseconds"
    )
    warnings: list[str] = Field(
        default_factory=list, description="Warnings or non-fatal errors"
    )
    dto: T | None = Field(default=None, description="Stage output DTO if successful")


class EmailAnalysisResult(BaseDTO):
    """Universal immutable output object representing complete end-to-end email incident analysis."""

    # 1. Primary Identifiers & Metadata
    analysis_id: UUID = Field(default_factory=uuid4, description="Unique analysis UUID")
    raw_email_id: UUID = Field(description="Parent RawEmail UUID reference")
    account_id: UUID = Field(description="Associated EmailAccount UUID")
    tenant_id: UUID = Field(description="Associated Tenant UUID")
    message_id: str = Field(description="Provider message ID")
    pipeline_version: str = Field(
        default="1.0.0", description="Pipeline orchestrator version"
    )
    execution_mode: str = Field(
        default="PARALLEL", description="Execution mode: PARALLEL or SEQUENTIAL"
    )
    schema_version: str = Field(default="1.0.0", description="Result schema version")

    # 2. Consolidated Stage Outputs (Modules 6-11)
    parsed_email: ParsedEmail = Field(description="Module 6 MIME parsing output")
    transmission_analysis: TransmissionAnalysis = Field(
        description="Module 7 Header analysis output"
    )
    auth_verification: AuthenticationVerification = Field(
        description="Module 8 Auth verification output"
    )
    threat_intel: ThreatIntelEnrichmentResult = Field(
        description="Module 9 Threat intel output"
    )
    risk_assessment: RiskAssessment = Field(
        description="Module 10 Risk assessment output"
    )
    decision_plan: DecisionPlan = Field(description="Module 11 AI decision plan output")

    # 3. SLA & Execution Telemetry
    sla_metrics: dict[str, float] = Field(
        default_factory=dict, description="Execution time per stage in ms"
    )
    sla_breached: bool = Field(
        default=False, description="Flag indicating if any SLA threshold was exceeded"
    )
    breached_stages: list[str] = Field(
        default_factory=list, description="Names of stages exceeding SLA budgets"
    )
    total_execution_time_ms: float = Field(
        default=0.0, description="Total pipeline execution time in ms"
    )
