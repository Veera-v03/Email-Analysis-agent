"""Asynchronous Slack notification channel using Slack Block Kit."""

from __future__ import annotations

import time
from typing import Any

import httpx

from src.config.enterprise_config import settings
from src.config.logging import get_logger
from src.notifications.channels.base import IAsyncNotificationChannel
from src.notifications.models import (
    ChannelDeliveryResultDTO,
    ChannelType,
    DeliveryStatus,
    NotificationPayloadDTO,
    TenantNotificationConfigDTO,
)

logger = get_logger("scamon.notifications.slack")


class SlackAsyncChannel(IAsyncNotificationChannel):
    """Posts formatted security alerts to Slack Incoming Webhooks via Block Kit."""

    def __init__(self, default_webhook_url: str | None = None, timeout_sec: float = 5.0) -> None:
        self.default_webhook_url = default_webhook_url
        self.timeout_sec = timeout_sec

    @property
    def channel_type(self) -> ChannelType:
        return ChannelType.SLACK

    def format_block_kit(self, payload: NotificationPayloadDTO) -> dict[str, Any]:
        """Generate Slack Block Kit payload from notification DTO."""
        severity_emoji = {
            "critical": "🚨",
            "high": "🔴",
            "medium": "🟠",
            "info": "ℹ️",
            "low": "🟢",
        }.get(payload.priority.value.lower(), "ℹ️")

        fields = [
            {"type": "mrkdwn", "text": f"*Tenant:* `{payload.tenant_id}`"},
            {"type": "mrkdwn", "text": f"*Priority:* `{payload.priority.value.upper()}`"},
        ]
        if payload.incident_id:
            fields.append({"type": "mrkdwn", "text": f"*Incident:* `{payload.incident_id}`"})
        if payload.message_id:
            fields.append({"type": "mrkdwn", "text": f"*Message ID:* `{payload.message_id}`"})

        blocks: list[dict[str, Any]] = [
            {
                "type": "header",
                "text": {
                    "type": "plain_text",
                    "text": f"{severity_emoji} {payload.title[:150]}",
                    "emoji": True,
                },
            },
            {
                "type": "section",
                "text": {
                    "type": "mrkdwn",
                    "text": payload.message,
                },
                "fields": fields,
            },
            {
                "type": "context",
                "elements": [
                    {
                        "type": "mrkdwn",
                        "text": f"Event: `{payload.event_name}` | Timestamp: `{payload.timestamp}`",
                    }
                ],
            },
        ]
        return {"blocks": blocks}

    async def send_async(
        self,
        payload: NotificationPayloadDTO,
        config: TenantNotificationConfigDTO | None = None,
    ) -> ChannelDeliveryResultDTO:
        start_time = time.perf_counter()
        webhook_url = (
            (config.slack_webhook_url if config else None)
            or self.default_webhook_url
            or settings.slack_webhook_url
            or settings.get_secret("SLACK_WEBHOOK_URL")
        )

        if not webhook_url:
            return ChannelDeliveryResultDTO(
                channel=self.channel_type,
                status=DeliveryStatus.SKIPPED,
                latency_ms=(time.perf_counter() - start_time) * 1000.0,
                error="Slack webhook URL not configured.",
            )

        body = self.format_block_kit(payload)

        try:
            async with httpx.AsyncClient(timeout=self.timeout_sec) as client:
                res = await client.post(webhook_url, json=body)
                elapsed_ms = (time.perf_counter() - start_time) * 1000.0

                if res.is_success:
                    return ChannelDeliveryResultDTO(
                        channel=self.channel_type,
                        status=DeliveryStatus.DELIVERED,
                        latency_ms=elapsed_ms,
                        status_code=res.status_code,
                    )
                else:
                    return ChannelDeliveryResultDTO(
                        channel=self.channel_type,
                        status=DeliveryStatus.FAILED,
                        latency_ms=elapsed_ms,
                        status_code=res.status_code,
                        error=f"Slack HTTP error {res.status_code}: {res.text[:200]}",
                    )
        except Exception as exc:
            elapsed_ms = (time.perf_counter() - start_time) * 1000.0
            logger.warning("Slack notification delivery failed: %s", exc)
            return ChannelDeliveryResultDTO(
                channel=self.channel_type,
                status=DeliveryStatus.FAILED,
                latency_ms=elapsed_ms,
                error=str(exc),
            )
