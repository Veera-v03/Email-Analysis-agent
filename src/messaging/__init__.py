"""Messaging infrastructure package for ScamON Enterprise Modular Monolith."""

from __future__ import annotations

from src.messaging.dispatcher import EventDispatcher
from src.messaging.event_bus import InMemoryEventBus, register_event_bus
from src.messaging.exceptions import (
    EventDispatchError,
    MessagingError,
    MiddlewareError,
    SubscriberNotFoundError,
)
from src.messaging.middleware import (
    ErrorHandlingMiddleware,
    EventMiddleware,
    LoggingMiddleware,
    MetricsMiddleware,
)
from src.messaging.publisher import EventPublisher
from src.messaging.subscriber import EventSubscriber

__all__ = [
    "ErrorHandlingMiddleware",
    "EventDispatchError",
    "EventDispatcher",
    "EventMiddleware",
    "EventPublisher",
    "EventSubscriber",
    "InMemoryEventBus",
    "LoggingMiddleware",
    "MessagingError",
    "MetricsMiddleware",
    "MiddlewareError",
    "SubscriberNotFoundError",
    "register_event_bus",
]
