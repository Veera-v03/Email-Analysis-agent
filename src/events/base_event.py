"""Base event schema definition for ScamON Enterprise messaging bus."""

from __future__ import annotations

from typing import Any
from uuid import UUID, uuid4

from pydantic import Field

from src.common.models import BaseEventDTO


class BaseEvent(BaseEventDTO):
    """Immutable base event type for all ScamON Enterprise events."""

    correlation_id: UUID = Field(
        default_factory=uuid4,
        description="Correlation ID for end-to-end distributed tracing",
    )
    metadata: dict[str, Any] = Field(
        default_factory=dict,
        description="Extensible contextual metadata payload",
    )
