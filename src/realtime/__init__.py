"""Real-Time SOC Event Stream Package (Module 22)."""

from __future__ import annotations

from src.realtime.broadcaster import (
    ClientConnectionState,
    SOCEventBroadcaster,
    WebSocketClient,
    get_event_broadcaster,
)
from src.realtime.module import (
    RealtimeModule,
    register_realtime_module,
)
from src.realtime.router import realtime_router

__all__ = [
    "SOCEventBroadcaster",
    "WebSocketClient",
    "ClientConnectionState",
    "get_event_broadcaster",
    "RealtimeModule",
    "register_realtime_module",
    "realtime_router",
]
