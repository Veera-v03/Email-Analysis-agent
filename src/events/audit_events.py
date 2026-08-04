"""Audit and compliance event contracts matching SAS v1.1.0."""

from __future__ import annotations

from typing import Any
from uuid import UUID

from pydantic import Field

from src.events.base_event import BaseEvent


class SecurityAuditEvent(BaseEvent):
    """Event emitted for immutable cryptographic audit logging."""

    event_type: str = "scamon.prod.audit.security.v1"
    actor_user_id: UUID | None = Field(
        default=None, description="User UUID performing action if applicable"
    )
    action: str = Field(description="Audit action description string")
    resource: str = Field(description="Target resource identifier")
    details: dict[str, Any] = Field(
        default_factory=dict, description="Audit action metadata"
    )


class PolicyTriggeredEvent(BaseEvent):
    """Event emitted when a tenant security policy threshold triggers."""

    event_type: str = "scamon.prod.audit.policy.v1"
    incident_id: UUID = Field(description="Associated incident record UUID")
    policy_rule: str = Field(description="Name of triggered tenant policy rule")
    threshold_value: int = Field(description="Trigger threshold value")
    actual_value: int = Field(description="Evaluated value")


class ActionExecutedEvent(BaseEvent):
    """Event emitted after executing an action (Clawback, Quarantine, Banner)."""

    event_type: str = "scamon.prod.audit.action.v1"
    incident_id: UUID = Field(description="Associated incident record UUID")
    action_type: str = Field(
        description="Action executed: CLAWBACK, QUARANTINE, BANNER"
    )
    status: str = Field(description="Action result status: SUCCESS, FAILED")
    affected_mailboxes_count: int = Field(
        default=0, description="Count of updated mailboxes"
    )
