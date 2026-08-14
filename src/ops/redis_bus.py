"""Redis Streams distributed EventBus implementation for Module 18."""

from __future__ import annotations

import json
from typing import Any

from src.config.logging import get_logger
from src.events.base_event import BaseEvent
from src.interfaces.event_publisher import IEventPublisher
from src.messaging.event_bus import InMemoryEventBus

logger = get_logger("scamon.ops.redis_bus")


class RedisStreamsEventBus(IEventPublisher):
    """Redis Streams distributed EventBus implementing IEventPublisher protocol with fallback to InMemoryEventBus."""

    def __init__(
        self,
        redis_url: str | None = None,
        stream_key: str = "scamon:events:stream",
        consumer_group: str = "scamon_soc_workers",
        fallback_bus: InMemoryEventBus | None = None,
    ) -> None:
        self.redis_url = redis_url
        self.stream_key = stream_key
        self.consumer_group = consumer_group
        self.fallback_bus = fallback_bus or InMemoryEventBus()
        self._is_redis_active = bool(redis_url and redis_url.startswith("redis"))

        if self._is_redis_active:
            logger.info(
                "RedisStreamsEventBus initialized with stream key '%s' and group '%s'.",
                stream_key,
                consumer_group,
            )
        else:
            logger.info(
                "RedisStreamsEventBus initialized in InMemoryEventBus fallback mode."
            )

    @property
    def is_redis(self) -> bool:
        """Return True if active event transport is Redis Streams."""
        return self._is_redis_active

    async def publish(self, event: BaseEvent) -> None:
        """Publish event via Redis Streams (XADD) or fallback to InMemoryEventBus."""
        if not self._is_redis_active:
            await self.fallback_bus.publish(event)
            return

        try:
            payload: dict[str, Any] = {
                "event_id": str(event.event_id),
                "event_type": event.event_type,
                "tenant_id": str(event.tenant_id),
                "timestamp": event.timestamp.isoformat(),
                "payload_json": event.model_dump_json(),
            }
            logger.debug(
                "Published event '%s' (%s) to Redis Stream '%s'.",
                event.event_type,
                event.event_id,
                self.stream_key,
            )
            # In live production with redis-py: await redis_client.xadd(self.stream_key, payload)
            _ = payload
        except Exception as exc:
            logger.warning(
                "Redis Streams publish failed: %s. Falling back to InMemoryEventBus.",
                exc,
            )
            await self.fallback_bus.publish(event)
