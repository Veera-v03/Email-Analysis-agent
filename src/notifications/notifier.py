"""Enterprise notification channels and backward-compatible synchronous dispatcher."""

from __future__ import annotations

import asyncio
from abc import ABC, abstractmethod
from typing import Any

from src.config.enterprise_config import settings
from src.notifications.channels.email import EmailAsyncChannel
from src.notifications.channels.slack import SlackAsyncChannel
from src.notifications.channels.teams import TeamsAsyncChannel
from src.notifications.channels.webhook import WebhookAsyncChannel
from src.notifications.models import (
    NotificationPayloadDTO,
    NotificationPriority,
)
from src.utils.logging import get_logger

logger = get_logger(__name__)


class NotificationEvent:
    """Represents a SOC notification message payload (Legacy & Modern compatible)."""

    def __init__(
        self,
        event_name: str,
        title: str,
        message: str,
        severity: str = "info",
        metadata: dict[str, Any] | None = None,
    ) -> None:
        self.event_name = event_name
        self.title = title
        self.message = message
        self.severity = severity
        self.metadata = metadata or {}

    def to_dto(self, tenant_id: str = "default_org") -> NotificationPayloadDTO:
        """Convert to modern NotificationPayloadDTO."""
        priority_map = {
            "critical": NotificationPriority.CRITICAL,
            "high": NotificationPriority.HIGH,
            "medium": NotificationPriority.MEDIUM,
            "low": NotificationPriority.LOW,
            "info": NotificationPriority.INFO,
        }
        prio = priority_map.get(self.severity.lower(), NotificationPriority.INFO)
        tenant = str(self.metadata.get("tenant_id", tenant_id))

        return NotificationPayloadDTO(
            tenant_id=tenant,
            event_name=self.event_name,
            title=self.title,
            message=self.message,
            priority=prio,
            metadata=self.metadata,
        )


class INotificationChannel(ABC):
    """Abstract interface for dispatching notifications to a destination channel."""

    @abstractmethod
    def send(self, event: NotificationEvent) -> bool:
        """Send notification. Returns True if successful."""


class EmailNotificationChannel(INotificationChannel):
    """SMTP mail delivery alerts channel adapter."""

    def __init__(self, recipient: str = "soc-alerts@enterprise.com") -> None:
        self.recipient = recipient
        self._async_channel = EmailAsyncChannel(default_recipients=[recipient])

    def send(self, event: NotificationEvent) -> bool:
        logger.info(
            "SMTP notification sent to %s. Subject: [%s] %s. Body: %s",
            self.recipient,
            event.severity.upper(),
            event.title,
            event.message,
        )
        return True


class WebhookNotificationChannel(INotificationChannel):
    """Outbound REST webhook endpoints channel adapter."""

    def __init__(self, endpoint_url: str | None = None) -> None:
        self.url = endpoint_url
        self._async_channel = WebhookAsyncChannel(default_webhook_url=endpoint_url)

    def send(self, event: NotificationEvent) -> bool:
        url = self.url or settings.get_secret("WEBHOOK_URL")
        if not url:
            logger.debug("Outbound Webhook URL not configured. Skipping.")
            return False

        try:
            dto = event.to_dto()
            # If inside running event loop, schedule task; otherwise run synchronously
            try:
                loop = asyncio.get_running_loop()
                loop.create_task(self._async_channel.send_async(dto))
            except RuntimeError:
                asyncio.run(self._async_channel.send_async(dto))
            return True
        except Exception as e:
            logger.error("Outbound Webhook delivery failed: %s", e)
            return False


class SlackNotificationChannel(INotificationChannel):
    """Slack Webhook channel adapter."""

    def __init__(self, webhook_url: str | None = None) -> None:
        self.webhook_url = webhook_url
        self._async_channel = SlackAsyncChannel(default_webhook_url=webhook_url)

    def send(self, event: NotificationEvent) -> bool:
        url = self.webhook_url or settings.slack_webhook_url
        if not url:
            return False

        try:
            dto = event.to_dto()
            try:
                loop = asyncio.get_running_loop()
                loop.create_task(self._async_channel.send_async(dto))
            except RuntimeError:
                asyncio.run(self._async_channel.send_async(dto))
            return True
        except Exception as e:
            logger.error("Slack webhook execution failed: %s", e)
            return False


class TeamsNotificationChannel(INotificationChannel):
    """Microsoft Teams Webhook channel adapter."""

    def __init__(self, webhook_url: str | None = None) -> None:
        self.webhook_url = webhook_url
        self._async_channel = TeamsAsyncChannel(default_webhook_url=webhook_url)

    def send(self, event: NotificationEvent) -> bool:
        url = self.webhook_url or settings.teams_webhook_url
        if not url:
            return False

        try:
            dto = event.to_dto()
            try:
                loop = asyncio.get_running_loop()
                loop.create_task(self._async_channel.send_async(dto))
            except RuntimeError:
                asyncio.run(self._async_channel.send_async(dto))
            return True
        except Exception as e:
            logger.error("Teams Webhook execution failed: %s", e)
            return False


class NotificationDispatcher:
    """Manages dispatch configurations and propagates messages to target channels."""

    def __init__(self, channels: list[INotificationChannel] | None = None) -> None:
        self._channels: list[INotificationChannel] = channels or [EmailNotificationChannel()]

    def register_channel(self, channel: INotificationChannel) -> None:
        """Register a notification delivery channel."""
        self._channels.append(channel)

    def dispatch(self, event: NotificationEvent) -> None:
        """Dispatch the event to all registered channels."""
        for chan in self._channels:
            try:
                chan.send(event)
            except Exception as e:
                logger.error(
                    "Failed to deliver notification via %s: %s",
                    chan.__class__.__name__,
                    e,
                )
