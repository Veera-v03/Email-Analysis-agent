"""Event subscriber interface contract for ScamON Enterprise."""

from __future__ import annotations

from collections.abc import Awaitable, Callable
from typing import Protocol, TypeVar, runtime_checkable

from src.events.base_event import BaseEvent
from src.interfaces.event_handler import IEventHandler

E = TypeVar("E", bound=BaseEvent)
HandlerType = IEventHandler[E] | Callable[[E], Awaitable[None]]


@runtime_checkable
class IEventSubscriber(Protocol):
    """Protocol for managing event subscriptions on the messaging bus."""

    def subscribe[E: BaseEvent](
        self,
        event_type: type[E],
        handler: IEventHandler[E] | Callable[[E], Awaitable[None]],
    ) -> None:
        """Register a handler callback or object for a specific event type."""
        ...

    def unsubscribe[E: BaseEvent](
        self,
        event_type: type[E],
        handler: IEventHandler[E] | Callable[[E], Awaitable[None]],
    ) -> None:
        """Remove a registered handler callback or object for an event type."""
        ...
