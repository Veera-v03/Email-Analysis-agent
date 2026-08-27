"""Pydantic data models and DTOs for Module 20 Enterprise SOC Alerting Engine."""

from __future__ import annotations

from datetime import UTC, datetime
from enum import StrEnum
from typing import Any
from uuid import UUID, uuid4

from pydantic import BaseModel, ConfigDict, Field, SecretStr


class ChannelType(StrEnum):
    """Supported notification output channel types."""

    SLACK = "slack"
    TEAMS = "teams"
    WEBHOOK = "webhook"
    EMAIL = "email"


class NotificationPriority(StrEnum):
    """Priority level for alert dispatching and filtering."""

    LOW = "low"
    INFO = "info"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class DeliveryStatus(StrEnum):
    """Individual channel delivery status."""

    DELIVERED = "DELIVERED"
    FAILED = "FAILED"
    RATE_LIMITED = "RATE_LIMITED"
    SUPPRESSED = "SUPPRESSED"
    SKIPPED = "SKIPPED"


class NotificationPayloadDTO(BaseModel):
    """Normalized, sanitized notification payload for multi-channel dispatch."""

    model_config = ConfigDict(extra="forbid", strict=True)

    notification_id: UUID = Field(default_factory=uuid4, description="Unique notification ID")
    tenant_id: str = Field(..., description="Target tenant organization identifier")
    event_name: str = Field(..., description="Event classification name, e.g., remediation_executed")
    title: str = Field(..., description="Concise alert title")
    message: str = Field(..., description="Sanitized human-readable message body")
    priority: NotificationPriority = Field(default=NotificationPriority.INFO, description="Alert priority")
    incident_id: str | None = Field(default=None, description="Related incident or investigation ID")
    message_id: str | None = Field(default=None, description="Target email message identifier")
    metadata: dict[str, Any] = Field(default_factory=dict, description="Sanitized contextual key-value metadata")
    timestamp: str = Field(
        default_factory=lambda: datetime.now(UTC).isoformat(),
        description="ISO-8601 UTC timestamp of creation",
    )


class ChannelDeliveryResultDTO(BaseModel):
    """Result of an outbound dispatch attempt to a single channel."""

    model_config = ConfigDict(arbitrary_types_allowed=True, extra="ignore")

    channel: ChannelType = Field(..., description="Target channel type")
    status: DeliveryStatus = Field(..., description="Delivery outcome status")
    latency_ms: float = Field(default=0.0, ge=0.0, description="Network and formatting latency in ms")
    status_code: int | None = Field(default=None, description="HTTP status code or protocol response code")
    error: str | None = Field(default=None, description="Error message if delivery failed")
    retries_attempted: int = Field(default=0, ge=0, description="Count of retry attempts executed")
    timestamp: str = Field(
        default_factory=lambda: datetime.now(UTC).isoformat(),
        description="ISO-8601 UTC timestamp of dispatch result",
    )


class DispatchSummaryDTO(BaseModel):
    """Consolidated multi-channel dispatch summary across all attempted channels."""

    model_config = ConfigDict(arbitrary_types_allowed=True, extra="ignore")

    notification_id: UUID = Field(..., description="Dispatched notification identifier")
    tenant_id: str = Field(..., description="Tenant organization identifier")
    event_name: str = Field(..., description="Event classification name")
    delivered_channels: list[ChannelType] = Field(default_factory=list, description="Channels that succeeded")
    failed_channels: list[ChannelType] = Field(default_factory=list, description="Channels that failed")
    channel_results: dict[str, Any] = Field(
        default_factory=dict, description="Detailed per-channel delivery results"
    )
    total_duration_ms: float = Field(default=0.0, ge=0.0, description="Total dispatch execution time in ms")
    is_suppressed: bool = Field(default=False, description="True if alert was suppressed by deduplication")


class TenantNotificationConfigDTO(BaseModel):
    """Tenant-specific notification and routing configuration."""

    model_config = ConfigDict(extra="ignore")

    tenant_id: str = Field(..., description="Tenant organization identifier")
    enabled_channels: list[ChannelType] = Field(
        default_factory=lambda: [ChannelType.SLACK, ChannelType.TEAMS, ChannelType.WEBHOOK, ChannelType.EMAIL],
        description="Active channels for this tenant",
    )
    slack_webhook_url: str | None = Field(default=None, description="Tenant-scoped Slack Incoming Webhook URL")
    teams_webhook_url: str | None = Field(default=None, description="Tenant-scoped Microsoft Teams Webhook URL")
    generic_webhook_url: str | None = Field(default=None, description="Tenant-scoped generic outbound webhook URL")
    webhook_signing_secret: SecretStr | None = Field(default=None, description="HMAC-SHA256 signing secret")
    email_recipients: list[str] = Field(
        default_factory=lambda: ["soc-alerts@enterprise.com"],
        description="Target email recipients for SMTP notifications",
    )
    rate_limit_per_minute: int = Field(default=60, ge=1, le=1000, description="Max alerts dispatched per minute")
    threat_dedup_window_sec: int = Field(default=300, ge=0, description="Time window in seconds to suppress duplicate alerts")
