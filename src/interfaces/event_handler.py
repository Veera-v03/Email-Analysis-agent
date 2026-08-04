"""Event handler protocol contract for ScamON Enterprise."""

from __future__ import annotations

from typing import Protocol, TypeVar, runtime_checkable

# pyrefly: ignore [missing-import]
from src.events.base_event import BaseEvent

E = TypeVar("E", bound=BaseEvent, contravariant=True)


@runtime_checkable
class IEventHandler[E: BaseEvent](Protocol):
    """Protocol for event handlers consuming specific typed events."""

    async def handle(self, event: E) -> None:
        """Process consumed event payload asynchronously."""
        ...
