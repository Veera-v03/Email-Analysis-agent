"""IAM security event payload contracts matching SAS v1.1.0."""

from __future__ import annotations

from uuid import UUID

from pydantic import Field

from src.events.base_event import BaseEvent


class UserLoggedInEvent(BaseEvent):
    """Event emitted when a user successfully authenticates."""

    event_type: str = "scamon.prod.iam.user.loggedin.v1"
    user_id: UUID = Field(description="Authenticated user UUID")
    email: str = Field(description="User email address")
    role: str = Field(description="User assigned RBAC role")
    ip_address: str | None = Field(default=None, description="Client IP address")


class UserLoginFailedEvent(BaseEvent):
    """Event emitted when user authentication fails."""

    event_type: str = "scamon.prod.iam.user.login_failed.v1"
    email: str = Field(description="Attempted email address")
    reason: str = Field(description="Failure description")
    ip_address: str | None = Field(default=None, description="Client IP address")


class TokenRefreshedEvent(BaseEvent):
    """Event emitted when an access token is refreshed."""

    event_type: str = "scamon.prod.iam.token.refreshed.v1"
    user_id: UUID = Field(description="User UUID")
    new_jti: UUID = Field(description="New access token JTI UUID")


class PermissionDeniedEvent(BaseEvent):
    """Event emitted when an authorization check fails."""

    event_type: str = "scamon.prod.iam.permission.denied.v1"
    user_id: UUID = Field(description="User UUID attempting operation")
    required_permission: str = Field(description="Required permission string")
    resource: str = Field(description="Target resource identifier")


class UserLoggedOutEvent(BaseEvent):
    """Event emitted when a user explicitly logs out."""

    event_type: str = "scamon.prod.iam.user.loggedout.v1"
    user_id: UUID = Field(description="User UUID logging out")
    jti: UUID = Field(description="Revoked token JTI UUID")
