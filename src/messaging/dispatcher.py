"""AsyncIO event dispatcher handling subscriber invocation and middleware chain."""

from __future__ import annotations

import asyncio
import time
from collections.abc import Awaitable, Callable
from typing import Any

from src.config.logging import get_logger
from src.events.base_event import BaseEvent
from src.interfaces.event_handler import IEventHandler
from src.messaging.middleware import EventMiddleware

logger = get_logger("scamon.messaging.dispatcher")

HandlerCallable = Callable[[Any], Awaitable[None]] | IEventHandler[Any]


class EventDispatcher:
    """Dispatches events asynchronously to registered handlers through middleware pipeline."""

    def __init__(self, middlewares: list[EventMiddleware] | None = None) -> None:
        self.middlewares: list[EventMiddleware] = middlewares or []

    def add_middleware(self, middleware: EventMiddleware) -> None:
        """Add a middleware instance to the dispatch pipeline."""
        self.middlewares.append(middleware)

    async def dispatch(self, event: BaseEvent, handlers: list[HandlerCallable]) -> None:
        """Dispatch event to a list of subscribers concurrently or sequentially with exception isolation."""
        if not handlers:
            logger.debug(
                "No subscribers registered for event type: %s", event.event_type
            )
            return

        # 1. Execute before_dispatch middleware hooks
        for mw in self.middlewares:
            try:
                await mw.before_dispatch(event)
            except Exception as exc:
                logger.error("Middleware before_dispatch error: %s", exc)

        start_time = time.perf_counter()

        # 2. Invoke subscriber handlers asynchronously with exception isolation
        tasks = [self._invoke_handler(handler, event) for handler in handlers]
        await asyncio.gather(*tasks, return_exceptions=True)

        elapsed_ms = (time.perf_counter() - start_time) * 1000

        # 3. Execute after_dispatch middleware hooks
        for mw in self.middlewares:
            try:
                await mw.after_dispatch(event, elapsed_ms)
            except Exception as exc:
                logger.error("Middleware after_dispatch error: %s", exc)

    async def _invoke_handler(self, handler: HandlerCallable, event: BaseEvent) -> None:
        """Invoke a single subscriber handler safely, trapping exceptions."""
        subscriber_name = getattr(handler, "__name__", handler.__class__.__name__)
        try:
            if isinstance(handler, IEventHandler):
                await handler.handle(event)
            elif callable(handler):
                res = handler(event)
                if hasattr(res, "__await__"):
                    await res
        except Exception as exc:
            logger.error(
                "Exception in subscriber handler '%s' for event '%s': %s",
                subscriber_name,
                event.event_type,
                exc,
            )
            for mw in self.middlewares:
                try:
                    await mw.on_error(event, subscriber_name, exc)
                except Exception as mw_err:
                    logger.error("Middleware on_error handler failed: %s", mw_err)
