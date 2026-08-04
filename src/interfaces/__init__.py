"""Interface contracts and abstractions for ScamON Enterprise."""

from __future__ import annotations

from src.interfaces.base import (
    IConfigurable,
    IHealthCheckable,
    IModule,
    IServiceContract,
)
from src.interfaces.event_handler import IEventHandler
from src.interfaces.event_publisher import IEventPublisher
from src.interfaces.event_subscriber import IEventSubscriber

__all__ = [
    "IConfigurable",
    "IEventHandler",
    "IEventPublisher",
    "IEventSubscriber",
    "IHealthCheckable",
    "IModule",
    "IServiceContract",
]
