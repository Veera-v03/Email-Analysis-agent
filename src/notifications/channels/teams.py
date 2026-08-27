"""Asynchronous Microsoft Teams notification channel using Adaptive Cards."""

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

logger = get_logger("scamon.notifications.teams")


class TeamsAsyncChannel(IAsyncNotificationChannel):
    """Posts formatted security alerts to Microsoft Teams Webhook connectors."""

    def __init__(self, default_webhook_url: str | None = None, timeout_sec: float = 5.0) -> None:
        self.default_webhook_url = default_webhook_url
        self.timeout_sec = timeout_sec

    @property
    def channel_type(self) -> ChannelType:
        return ChannelType.TEAMS

    def format_adaptive_card(self, payload: NotificationPayloadDTO) -> dict[str, Any]:
        """Generate Microsoft Teams MessageCard / Adaptive Card JSON payload."""
        theme_color = "FF0000" if payload.priority.value.lower() in ("critical", "high") else "0078D7"

        facts = [
            {"name": "Tenant ID:", "value": payload.tenant_id},
            {"name": "Priority:", "value": payload.priority.value.upper()},
            {"name": "Event:", "value": payload.event_name},
        ]
        if payload.incident_id:
            facts.append({"name": "Incident ID:", "value": payload.incident_id})
        if payload.message_id:
            facts.append({"name": "Message ID:", "value": payload.message_id})

        return {
            "@type": "MessageCard",
            "@context": "http://schema.org/extensions",
            "themeColor": theme_color,
            "summary": payload.title,
            "sections": [
                {
                    "activityTitle": f"🛡️ {payload.title}",
                    "activitySubtitle": f"Priority: {payload.priority.value.upper()} | Time: {payload.timestamp}",
                    "text": payload.message,
                    "facts": facts,
                    "markdown": True,
                }
            ],
        }

    async def send_async(
        self,
        payload: NotificationPayloadDTO,
        config: TenantNotificationConfigDTO | None = None,
    ) -> ChannelDeliveryResultDTO:
        start_time = time.perf_counter()
        webhook_url = (
            (config.teams_webhook_url if config else None)
            or self.default_webhook_url
            or settings.teams_webhook_url
            or settings.get_secret("TEAMS_WEBHOOK_URL")
        )

        if not webhook_url:
            return ChannelDeliveryResultDTO(
                channel=self.channel_type,
                status=DeliveryStatus.SKIPPED,
                latency_ms=(time.perf_counter() - start_time) * 1000.0,
                error="Microsoft Teams webhook URL not configured.",
            )

        body = self.format_adaptive_card(payload)

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
                        error=f"Teams HTTP error {res.status_code}: {res.text[:200]}",
                    )
        except Exception as exc:
            elapsed_ms = (time.perf_counter() - start_time) * 1000.0
            logger.warning("Microsoft Teams notification delivery failed: %s", exc)
            return ChannelDeliveryResultDTO(
                channel=self.channel_type,
                status=DeliveryStatus.FAILED,
                latency_ms=elapsed_ms,
                error=str(exc),
            )
