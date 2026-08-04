"""System operational event contracts matching SAS v1.1.0."""

from __future__ import annotations

from pydantic import Field

from src.events.base_event import BaseEvent


class SystemStartedEvent(BaseEvent):
    """Event emitted when system or microservice pod initializes."""

    event_type: str = "scamon.prod.system.started.v1"
    environment: str = Field(description="Deployment environment name")
    version: str = Field(description="Platform release version")


class SystemShutdownEvent(BaseEvent):
    """Event emitted when system initiates orderly shutdown."""

    event_type: str = "scamon.prod.system.shutdown.v1"
    reason: str = Field(default="Normal shutdown", description="Shutdown reason")


class ComponentDegradedEvent(BaseEvent):
    """Event emitted when a platform module or health check degrades."""

    event_type: str = "scamon.prod.system.degraded.v1"
    component_name: str = Field(description="Name of degraded component")
    error_message: str = Field(description="Failure or degradation description")
