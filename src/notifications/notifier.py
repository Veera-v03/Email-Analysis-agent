"""Enterprise notification channels sending security alerts via Email, Slack, Teams, and Custom Webhooks."""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Any

import requests

from src.config.enterprise_config import settings
from src.utils.logging import get_logger

logger = get_logger(__name__)


class NotificationEvent:
    """Represents a SOC notification message payload."""

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


class INotificationChannel(ABC):
    """Abstract interface for dispatching notifications to a destination channel."""

    @abstractmethod
    def send(self, event: NotificationEvent) -> bool:
        """Send notification. Returns True if successful."""


class EmailNotificationChannel(INotificationChannel):
    """Simulates enterprise SMTP mail delivery alerts."""

    def __init__(self, recipient: str = "soc-alerts@enterprise.com") -> None:
        self.recipient = recipient

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
    """Triggers outbound REST webhook endpoints."""

    def __init__(self, endpoint_url: str | None = None) -> None:
        self.url = endpoint_url

    def send(self, event: NotificationEvent) -> bool:
        url = self.url or settings.get_secret("WEBHOOK_URL")
        if not url:
            logger.debug("Outbound Webhook URL not configured. Skipping.")
            return False

        payload: dict[str, Any] = {
            "event": event.event_name,
            "title": event.title,
            "message": event.message,
            "severity": event.severity,
            "metadata": event.metadata,
        }
        try:
            res = requests.post(url, json=payload, timeout=5)
            return res.status_code in (200, 201, 202)
        except Exception as e:
            logger.error("Outbound Webhook delivery failed: %s", e)
            return False


class SlackNotificationChannel(INotificationChannel):
    """Posts formatted messages to Slack Webhook channels using Block Kit structure."""

    def __init__(self, webhook_url: str | None = None) -> None:
        self.webhook_url = webhook_url

    def send(self, event: NotificationEvent) -> bool:
        url = self.webhook_url or settings.slack_webhook_url
        if not url:
            return False

        # Slack Block Kit structure payload
        slack_payload: dict[str, Any] = {
            "blocks": [
                {
                    "type": "header",
                    "text": {
                        "type": "plain_text",
                        "text": f"🚨 {event.title}",
                        "emoji": True,
                    },
                },
                {
                    "type": "section",
                    "text": {
                        "type": "mrkdwn",
                        "text": f"*Severity:* `{event.severity.upper()}`\n\n{event.message}",
                    },
                },
            ]
        }
        try:
            res = requests.post(url, json=slack_payload, timeout=5)
            return res.status_code == 200
        except Exception as e:
            logger.error("Slack webhook execution failed: %s", e)
            return False


class TeamsNotificationChannel(INotificationChannel):
    """Posts formatted Adaptive Card messages to Microsoft Teams Webhook connectors."""

    def __init__(self, webhook_url: str | None = None) -> None:
        self.webhook_url = webhook_url

    def send(self, event: NotificationEvent) -> bool:
        url = self.webhook_url or settings.teams_webhook_url
        if not url:
            return False

        card_payload = {
            "@type": "MessageCard",
            "@context": "http://schema.org/extensions",
            "themeColor": "FF0000"
            if event.severity in ("high", "critical")
            else "0078D7",
            "summary": event.title,
            "sections": [
                {
                    "activityTitle": event.title,
                    "activitySubtitle": f"Severity: {event.severity.upper()}",
                    "text": event.message,
                }
            ],
        }
        try:
            res = requests.post(url, json=card_payload, timeout=5)
            return res.status_code == 200
        except Exception as e:
            logger.error("Teams Webhook execution failed: %s", e)
            return False


class NotificationDispatcher:
    """Manages dispatch configurations and propagates messages to target channels."""

    def __init__(self) -> None:
        self._channels: list[INotificationChannel] = [EmailNotificationChannel()]

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
