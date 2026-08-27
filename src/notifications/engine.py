"""NotificationEngine coordinating asynchronous multi-channel dispatch with retries, rate-limiting, and deduplication."""

from __future__ import annotations

import asyncio
import random
import time
from collections import defaultdict
from typing import Any
from uuid import UUID

from src.config.enterprise_config import settings
from src.config.logging import get_logger
from src.notifications.channels.base import IAsyncNotificationChannel
from src.notifications.channels.email import EmailAsyncChannel
from src.notifications.channels.slack import SlackAsyncChannel
from src.notifications.channels.teams import TeamsAsyncChannel
from src.notifications.channels.webhook import WebhookAsyncChannel
from src.notifications.exceptions import RateLimitExceededError
from src.notifications.models import (
    ChannelDeliveryResultDTO,
    ChannelType,
    DeliveryStatus,
    DispatchSummaryDTO,
    NotificationPayloadDTO,
    TenantNotificationConfigDTO,
)
from src.notifications.sanitizer import sanitize_payload

logger = get_logger("scamon.notifications.engine")


class NotificationEngine:
    """Enterprise SOC notification and webhook dispatch engine."""

    def __init__(
        self,
        channels: dict[ChannelType, IAsyncNotificationChannel] | None = None,
        max_retries: int = 3,
        retry_backoff_sec: float = 0.5,
        default_rate_limit: int = 60,
    ) -> None:
        self.max_retries = max_retries
        self.retry_backoff_sec = retry_backoff_sec
        self.default_rate_limit = default_rate_limit

        # Default channel adapters
        self._channels: dict[ChannelType, IAsyncNotificationChannel] = channels or {
            ChannelType.SLACK: SlackAsyncChannel(),
            ChannelType.TEAMS: TeamsAsyncChannel(),
            ChannelType.WEBHOOK: WebhookAsyncChannel(),
            ChannelType.EMAIL: EmailAsyncChannel(),
        }

        # Tenant configs cache: tenant_id -> TenantNotificationConfigDTO
        self._tenant_configs: dict[str, TenantNotificationConfigDTO] = {}

        # Rate limiting state: tenant_id -> list of timestamps
        self._rate_limit_records: dict[str, list[float]] = defaultdict(list)

        # Deduplication cache: dedup_key -> expiry_timestamp
        self._dedup_cache: dict[str, float] = {}

        # Operational metrics
        self._dispatched_count: int = 0
        self._delivered_count: int = 0
        self._failed_count: int = 0
        self._suppressed_count: int = 0
        self._rate_limited_count: int = 0

    def register_channel(self, channel: IAsyncNotificationChannel) -> None:
        """Register or override a channel adapter."""
        self._channels[channel.channel_type] = channel

    def set_tenant_config(self, config: TenantNotificationConfigDTO) -> None:
        """Register or update tenant-specific routing configurations."""
        self._tenant_configs[config.tenant_id] = config

    def get_tenant_config(self, tenant_id: str) -> TenantNotificationConfigDTO:
        """Retrieve tenant configuration or return default fallback."""
        if tenant_id in self._tenant_configs:
            return self._tenant_configs[tenant_id]
        return TenantNotificationConfigDTO(
            tenant_id=tenant_id,
            rate_limit_per_minute=self.default_rate_limit,
        )

    def _check_rate_limit(self, tenant_id: str, limit_per_minute: int) -> bool:
        """Evaluate sliding window rate limit for tenant. Returns True if allowed, False if exceeded."""
        now = time.time()
        window_start = now - 60.0

        # Purge expired timestamps
        records = [ts for ts in self._rate_limit_records[tenant_id] if ts > window_start]
        self._rate_limit_records[tenant_id] = records

        if len(records) >= limit_per_minute:
            return False

        records.append(now)
        return True

    def _check_and_update_dedup(
        self,
        tenant_id: str,
        event_name: str,
        incident_id: str | None,
        message_id: str | None,
        window_sec: int,
    ) -> bool:
        """Check if identical alert was dispatched recently. Returns True if duplicate (should suppress)."""
        if window_sec <= 0:
            return False

        now = time.time()
        target_id = incident_id or message_id
        if not target_id:
            return False

        dedup_key = f"{tenant_id}:{event_name}:{target_id}"

        # Clean expired keys
        expired_keys = [k for k, exp in self._dedup_cache.items() if exp <= now]
        for k in expired_keys:
            del self._dedup_cache[k]

        if dedup_key in self._dedup_cache and self._dedup_cache[dedup_key] > now:
            return True

        self._dedup_cache[dedup_key] = now + window_sec
        return False

    async def _send_with_retries(
        self,
        channel: IAsyncNotificationChannel,
        payload: NotificationPayloadDTO,
        config: TenantNotificationConfigDTO,
    ) -> ChannelDeliveryResultDTO:
        """Execute channel send with bounded exponential backoff and jitter."""
        attempt = 0
        last_result: ChannelDeliveryResultDTO | None = None

        while attempt <= self.max_retries:
            try:
                res = await channel.send_async(payload, config)
                res.retries_attempted = attempt

                if res.status in (DeliveryStatus.DELIVERED, DeliveryStatus.SKIPPED):
                    return res

                last_result = res
            except Exception as exc:
                last_result = ChannelDeliveryResultDTO(
                    channel=channel.channel_type,
                    status=DeliveryStatus.FAILED,
                    error=str(exc),
                    retries_attempted=attempt,
                )

            attempt += 1
            if attempt <= self.max_retries:
                backoff = self.retry_backoff_sec * (2 ** (attempt - 1))
                jitter = random.uniform(0.05, 0.2) * backoff
                await asyncio.sleep(backoff + jitter)

        return last_result or ChannelDeliveryResultDTO(
            channel=channel.channel_type,
            status=DeliveryStatus.FAILED,
            error="Max retries exceeded",
            retries_attempted=self.max_retries,
        )

    async def dispatch(
        self,
        payload: NotificationPayloadDTO,
        channels: list[ChannelType] | None = None,
        tenant_config: TenantNotificationConfigDTO | None = None,
    ) -> DispatchSummaryDTO:
        """Asynchronously dispatch sanitized notification payload across configured channels."""
        start_time = time.perf_counter()
        self._dispatched_count += 1

        # 1. Resolve Tenant Configuration
        config = tenant_config or self.get_tenant_config(payload.tenant_id)

        # 2. Check Global / Tenant Rate Limiting
        rate_limit = config.rate_limit_per_minute or self.default_rate_limit
        if not self._check_rate_limit(payload.tenant_id, rate_limit):
            self._rate_limited_count += 1
            logger.warning(
                "Notification rate limit (%d/min) exceeded for tenant '%s'",
                rate_limit,
                payload.tenant_id,
            )
            elapsed_ms = (time.perf_counter() - start_time) * 1000.0
            return DispatchSummaryDTO(
                notification_id=payload.notification_id,
                tenant_id=payload.tenant_id,
                event_name=payload.event_name,
                failed_channels=channels or config.enabled_channels,
                channel_results={
                    ch.value: ChannelDeliveryResultDTO(
                        channel=ch,
                        status=DeliveryStatus.RATE_LIMITED,
                        error=f"Rate limit of {rate_limit} msgs/min exceeded",
                    )
                    for ch in (channels or config.enabled_channels)
                },
                total_duration_ms=elapsed_ms,
            )

        # 3. Check Deduplication / Suppression
        if self._check_and_update_dedup(
            tenant_id=payload.tenant_id,
            event_name=payload.event_name,
            incident_id=payload.incident_id,
            message_id=payload.message_id,
            window_sec=config.threat_dedup_window_sec,
        ):
            self._suppressed_count += 1
            logger.info(
                "Suppressed duplicate notification '%s' for tenant '%s'",
                payload.event_name,
                payload.tenant_id,
            )
            elapsed_ms = (time.perf_counter() - start_time) * 1000.0
            return DispatchSummaryDTO(
                notification_id=payload.notification_id,
                tenant_id=payload.tenant_id,
                event_name=payload.event_name,
                is_suppressed=True,
                total_duration_ms=elapsed_ms,
            )

        # 4. Mandatory PII Sanitization
        sanitized = sanitize_payload(payload)

        # 5. Resolve Target Channels
        target_channel_types = channels or config.enabled_channels
        active_channels = [
            self._channels[ch_type]
            for ch_type in target_channel_types
            if ch_type in self._channels
        ]

        # 6. Concurrent Async Dispatch Across Channels
        async def _dispatch_single(ch: IAsyncNotificationChannel) -> tuple[ChannelType, ChannelDeliveryResultDTO]:
            res = await self._send_with_retries(ch, sanitized, config)
            return ch.channel_type, res

        tasks = [_dispatch_single(ch) for ch in active_channels]
        results: list[tuple[ChannelType, ChannelDeliveryResultDTO]] = await asyncio.gather(*tasks, return_exceptions=False)

        # 7. Aggregate Summary
        delivered: list[ChannelType] = []
        failed: list[ChannelType] = []
        channel_results_map: dict[str, ChannelDeliveryResultDTO] = {}

        for ch_type, res in results:
            channel_results_map[ch_type.value] = res
            if res.status == DeliveryStatus.DELIVERED:
                delivered.append(ch_type)
                self._delivered_count += 1
            elif res.status == DeliveryStatus.FAILED:
                failed.append(ch_type)
                self._failed_count += 1

        elapsed_ms = (time.perf_counter() - start_time) * 1000.0

        return DispatchSummaryDTO(
            notification_id=sanitized.notification_id,
            tenant_id=sanitized.tenant_id,
            event_name=sanitized.event_name,
            delivered_channels=delivered,
            failed_channels=failed,
            channel_results=channel_results_map,
            total_duration_ms=elapsed_ms,
        )

    def get_metrics(self) -> dict[str, Any]:
        """Return operational telemetry metrics for health reporting."""
        return {
            "dispatched_count": self._dispatched_count,
            "delivered_count": self._delivered_count,
            "failed_count": self._failed_count,
            "suppressed_count": self._suppressed_count,
            "rate_limited_count": self._rate_limited_count,
            "active_channels": [ch.value for ch in self._channels.keys()],
        }
