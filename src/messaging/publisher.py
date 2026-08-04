"""Event publisher implementation wrapping event bus dispatch."""

from __future__ import annotations

from src.events.base_event import BaseEvent
from src.interfaces.event_publisher import IEventPublisher


class EventPublisher(IEventPublisher):
    """Event publisher implementation delegating to event bus instance."""

    def __init__(self, bus: IEventPublisher) -> None:
        self._bus = bus

    async def publish(self, event: BaseEvent) -> None:
        """Publish event via underlying event bus."""
        await self._bus.publish(event)
