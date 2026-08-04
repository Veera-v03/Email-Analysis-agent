"""Event publisher interface contract for ScamON Enterprise."""

from __future__ import annotations

from typing import Protocol, runtime_checkable

from src.events.base_event import BaseEvent


@runtime_checkable
class IEventPublisher(Protocol):
    """Protocol for components publishing events to the messaging bus."""

    async def publish(self, event: BaseEvent) -> None:
        """Publish an event to all registered bus subscribers asynchronously."""
        ...
