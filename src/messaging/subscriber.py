"""Event subscriber manager for handling subscription registrations."""

from __future__ import annotations

from collections.abc import Awaitable, Callable
from typing import Any

from src.events.base_event import BaseEvent
from src.interfaces.event_handler import IEventHandler
from src.interfaces.event_subscriber import IEventSubscriber

HandlerCallable = IEventHandler[Any] | Callable[[Any], Awaitable[None]]


class EventSubscriber(IEventSubscriber):
    """Manages subscription registries for event handlers."""

    def __init__(self) -> None:
        self._subscriptions: dict[type[BaseEvent], list[HandlerCallable]] = {}

    def subscribe[E: BaseEvent](
        self,
        event_type: type[E],
        handler: IEventHandler[E] | Callable[[E], Awaitable[None]],
    ) -> None:
        """Register a handler callback or object for a specific event type."""
        handlers = self._subscriptions.setdefault(event_type, [])
        if handler not in handlers:
            handlers.append(handler)

    def unsubscribe[E: BaseEvent](
        self,
        event_type: type[E],
        handler: IEventHandler[E] | Callable[[E], Awaitable[None]],
    ) -> None:
        """Remove a registered handler callback or object for an event type."""
        if event_type in self._subscriptions:
            handlers = self._subscriptions[event_type]
            if handler in handlers:
                handlers.remove(handler)

    def get_handlers_for(self, event_type: type[BaseEvent]) -> list[HandlerCallable]:
        """Retrieve all handlers registered for an event type (including parent event types)."""
        handlers: list[HandlerCallable] = []
        for reg_type, reg_handlers in self._subscriptions.items():
            if issubclass(event_type, reg_type):
                handlers.extend(reg_handlers)
        return handlers
