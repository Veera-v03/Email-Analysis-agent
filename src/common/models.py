"""Base DTO models and common schemas for ScamON Enterprise."""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any
from uuid import UUID, uuid4

from pydantic import BaseModel, ConfigDict, Field


class BaseDTO(BaseModel):
    """Base immutable Data Transfer Object (DTO) model."""

    model_config = ConfigDict(
        frozen=True,
        extra="forbid",
        populate_by_name=True,
        from_attributes=True,
    )


class BaseEventDTO(BaseDTO):
    """Standard event payload header schema for messaging contracts."""

    event_id: UUID = Field(default_factory=uuid4, description="Unique event ID")
    tenant_id: UUID = Field(description="Associated tenant UUID")
    event_type: str = Field(description="Fully qualified event type name")
    timestamp: datetime = Field(
        default_factory=lambda: datetime.now(UTC),
        description="Event creation timestamp",
    )
    version: str = Field(default="1.0.0", description="Event schema version")


class ComponentHealthDTO(BaseDTO):
    """Status report for a single system component or microservice module."""

    component_name: str = Field(description="Name of the component")
    status: str = Field(description="Component status: HEALTHY, DEGRADED, UNHEALTHY")
    latency_ms: float = Field(default=0.0, description="Health check latency in ms")
    details: dict[str, Any] = Field(
        default_factory=dict, description="Additional health details"
    )


class HealthStatusDTO(BaseDTO):
    """System-wide consolidated health status report."""

    status: str = Field(description="Overall system status: UP, DEGRADED, DOWN")
    environment: str = Field(description="Execution environment")
    timestamp: datetime = Field(
        default_factory=lambda: datetime.now(UTC),
        description="Health report timestamp",
    )
    components: list[ComponentHealthDTO] = Field(
        default_factory=list, description="Individual component health metrics"
    )


class ErrorDetailDTO(BaseDTO):
    """Standardized API error response DTO matching SAS v1.1.0 specification."""

    code: str = Field(description="Standard error code string")
    message: str = Field(description="Human readable error message")
    status: int = Field(description="HTTP status code")
    details: dict[str, Any] = Field(
        default_factory=dict, description="Contextual error details"
    )
    timestamp: datetime = Field(
        default_factory=lambda: datetime.now(UTC),
        description="Error timestamp",
    )
    trace_id: str | None = Field(default=None, description="Distributed trace ID")


class APIResponseDTO[T](BaseDTO):
    """Generic envelope for REST API responses."""

    success: bool = Field(default=True, description="Request execution success flag")
    data: T | None = Field(default=None, description="Response payload data")
    error: ErrorDetailDTO | None = Field(
        default=None, description="Error detail object if failed"
    )
