"""Asynchronous Generic Outbound Webhook channel with SSRF guardrails and HMAC-SHA256 signing."""

from __future__ import annotations

import hashlib
import hmac
import ipaddress
import json
import socket
import time
from typing import Any
from urllib.parse import urlparse

import httpx

from src.config.enterprise_config import settings
from src.config.logging import get_logger
from src.notifications.channels.base import IAsyncNotificationChannel
from src.notifications.exceptions import SSRFSecurityError
from src.notifications.models import (
    ChannelDeliveryResultDTO,
    ChannelType,
    DeliveryStatus,
    NotificationPayloadDTO,
    TenantNotificationConfigDTO,
)

logger = get_logger("scamon.notifications.webhook")

BLOCKED_IP_NETWORKS = [
    ipaddress.ip_network("127.0.0.0/8"),
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("169.254.0.0/16"),  # Link-local / Cloud metadata
    ipaddress.ip_network("0.0.0.0/8"),
    ipaddress.ip_network("::1/128"),
    ipaddress.ip_network("fc00::/7"),  # IPv6 Unique Local
    ipaddress.ip_network("fe80::/10"),  # IPv6 Link-Local
]

BLOCKED_HOSTNAMES = {
    "localhost",
    "metadata.google.internal",
    "metadata",
    "instance-data",
}


def validate_webhook_url_ssrf(url: str) -> None:
    """Validate that the target webhook URL is not targeting internal or private infrastructure."""
    parsed = urlparse(url)
    if parsed.scheme.lower() not in ("http", "https"):
        raise SSRFSecurityError(url, f"Unsupported URL scheme '{parsed.scheme}'. Only http/https permitted.")

    hostname = (parsed.hostname or "").lower()
    if not hostname or hostname in BLOCKED_HOSTNAMES or hostname.endswith(".internal") or hostname.endswith(".local"):
        raise SSRFSecurityError(url, f"Blocked hostname '{hostname}' is not permitted.")

    try:
        # Resolve all A / AAAA addresses for the target hostname
        addr_info = socket.getaddrinfo(hostname, None)
        resolved_ips = {info[4][0] for info in addr_info if info[4]}
    except socket.gaierror as err:
        raise SSRFSecurityError(url, f"DNS resolution failed for hostname '{hostname}': {err}") from err

    if not resolved_ips:
        raise SSRFSecurityError(url, f"No IP addresses resolved for hostname '{hostname}'.")

    for ip_str in resolved_ips:
        ip_obj = ipaddress.ip_address(ip_str)
        for net in BLOCKED_IP_NETWORKS:
            if ip_obj in net:
                raise SSRFSecurityError(url, f"Resolved IP '{ip_str}' belongs to restricted network '{net}'.")


def compute_hmac_signature(payload_json: str, secret: str, timestamp: str) -> str:
    """Compute HMAC-SHA256 signature for webhook payload."""
    signature_base = f"{timestamp}.{payload_json}".encode()
    return hmac.new(secret.encode(), signature_base, hashlib.sha256).hexdigest()


class WebhookAsyncChannel(IAsyncNotificationChannel):
    """Dispatches JSON security alerts to custom webhook endpoints with SSRF guardrails & HMAC signing."""

    def __init__(
        self,
        default_webhook_url: str | None = None,
        signing_secret: str | None = None,
        timeout_sec: float = 5.0,
        enforce_ssrf_check: bool = True,
    ) -> None:
        self.default_webhook_url = default_webhook_url
        self.signing_secret = signing_secret
        self.timeout_sec = timeout_sec
        self.enforce_ssrf_check = enforce_ssrf_check

    @property
    def channel_type(self) -> ChannelType:
        return ChannelType.WEBHOOK

    async def send_async(
        self,
        payload: NotificationPayloadDTO,
        config: TenantNotificationConfigDTO | None = None,
    ) -> ChannelDeliveryResultDTO:
        start_time = time.perf_counter()
        webhook_url = (
            (config.generic_webhook_url if config else None)
            or self.default_webhook_url
            or settings.get_secret("WEBHOOK_URL")
        )

        if not webhook_url:
            return ChannelDeliveryResultDTO(
                channel=self.channel_type,
                status=DeliveryStatus.SKIPPED,
                latency_ms=(time.perf_counter() - start_time) * 1000.0,
                error="Outbound Webhook URL not configured.",
            )

        # 1. SSRF Validation
        if self.enforce_ssrf_check:
            try:
                validate_webhook_url_ssrf(webhook_url)
            except SSRFSecurityError as ssrf_err:
                elapsed_ms = (time.perf_counter() - start_time) * 1000.0
                logger.error("SSRF check rejected webhook dispatch: %s", ssrf_err)
                return ChannelDeliveryResultDTO(
                    channel=self.channel_type,
                    status=DeliveryStatus.FAILED,
                    latency_ms=elapsed_ms,
                    error=str(ssrf_err),
                )

        # 2. Serialize Payload & Calculate HMAC Signature
        payload_data: dict[str, Any] = {
            "notification_id": str(payload.notification_id),
            "tenant_id": payload.tenant_id,
            "event_name": payload.event_name,
            "title": payload.title,
            "message": payload.message,
            "priority": payload.priority.value,
            "incident_id": payload.incident_id,
            "message_id": payload.message_id,
            "metadata": payload.metadata,
            "timestamp": payload.timestamp,
        }
        payload_json = json.dumps(payload_data, sort_keys=True)
        timestamp_str = str(int(time.time()))

        headers: dict[str, str] = {
            "Content-Type": "application/json",
            "User-Agent": "ScamON-Security-Notifier/1.0",
            "X-ScamON-Timestamp": timestamp_str,
            "X-ScamON-Event": payload.event_name,
            "X-ScamON-Tenant": payload.tenant_id,
        }

        # Resolve signing secret
        secret = (
            (config.webhook_signing_secret.get_secret_value() if config and config.webhook_signing_secret else None)
            or self.signing_secret
            or settings.get_secret("NOTIFICATION_WEBHOOK_SIGNING_SECRET")
        )
        if secret:
            sig_hex = compute_hmac_signature(payload_json, secret, timestamp_str)
            headers["X-ScamON-Signature"] = f"sha256={sig_hex}"

        # 3. Perform Asynchronous HTTP POST
        try:
            async with httpx.AsyncClient(timeout=self.timeout_sec) as client:
                res = await client.post(webhook_url, content=payload_json, headers=headers)
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
                        error=f"Webhook server returned HTTP {res.status_code}: {res.text[:200]}",
                    )
        except Exception as exc:
            elapsed_ms = (time.perf_counter() - start_time) * 1000.0
            logger.warning("Webhook notification delivery failed: %s", exc)
            return ChannelDeliveryResultDTO(
                channel=self.channel_type,
                status=DeliveryStatus.FAILED,
                latency_ms=elapsed_ms,
                error=str(exc),
            )
