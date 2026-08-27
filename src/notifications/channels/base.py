"""Abstract base interface for asynchronous notification channels."""

from __future__ import annotations

from abc import ABC, abstractmethod

from src.notifications.models import (
    ChannelDeliveryResultDTO,
    ChannelType,
    NotificationPayloadDTO,
    TenantNotificationConfigDTO,
)


class IAsyncNotificationChannel(ABC):
    """Abstract interface representing an asynchronous notification delivery channel."""

    @property
    @abstractmethod
    def channel_type(self) -> ChannelType:
        """Return the unique channel type."""

    @abstractmethod
    async def send_async(
        self,
        payload: NotificationPayloadDTO,
        config: TenantNotificationConfigDTO | None = None,
    ) -> ChannelDeliveryResultDTO:
        """Asynchronously deliver sanitized notification payload to destination."""
