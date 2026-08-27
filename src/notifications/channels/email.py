"""Asynchronous SMTP Email notification delivery channel."""

from __future__ import annotations

import asyncio
import smtplib
import time
from email.message import EmailMessage

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

logger = get_logger("scamon.notifications.email")


class EmailAsyncChannel(IAsyncNotificationChannel):
    """Sends enterprise email alerts via SMTP or non-blocking simulated logging."""

    def __init__(
        self,
        default_recipients: list[str] | None = None,
        smtp_host: str | None = None,
        smtp_port: int = 587,
        smtp_user: str | None = None,
        smtp_password: str | None = None,
        smtp_from: str = "soc-alerts@scamshield.enterprise",
        smtp_use_tls: bool = True,
        timeout_sec: float = 5.0,
    ) -> None:
        self.default_recipients = default_recipients or ["soc-alerts@enterprise.com"]
        self.smtp_host = smtp_host
        self.smtp_port = smtp_port
        self.smtp_user = smtp_user
        self.smtp_password = smtp_password
        self.smtp_from = smtp_from
        self.smtp_use_tls = smtp_use_tls
        self.timeout_sec = timeout_sec

    @property
    def channel_type(self) -> ChannelType:
        return ChannelType.EMAIL

    def _format_email_message(
        self,
        payload: NotificationPayloadDTO,
        recipients: list[str],
        from_address: str,
    ) -> EmailMessage:
        """Create structured EmailMessage standard payload."""
        msg = EmailMessage()
        msg["Subject"] = f"[{payload.priority.value.upper()}] {payload.title}"
        msg["From"] = from_address
        msg["To"] = ", ".join(recipients)

        body_text = (
            f"ScamON Enterprise Security Alert\n"
            f"----------------------------------------\n"
            f"Tenant: {payload.tenant_id}\n"
            f"Event: {payload.event_name}\n"
            f"Priority: {payload.priority.value.upper()}\n"
            f"Timestamp: {payload.timestamp}\n"
        )
        if payload.incident_id:
            body_text += f"Incident ID: {payload.incident_id}\n"
        if payload.message_id:
            body_text += f"Message ID: {payload.message_id}\n"

        body_text += (
            f"\nAlert Message:\n{payload.message}\n\n"
            f"Metadata:\n"
        )
        for k, v in payload.metadata.items():
            body_text += f"  - {k}: {v}\n"

        msg.set_content(body_text)
        return msg

    def _send_smtp_sync(
        self,
        msg: EmailMessage,
        host: str,
        port: int,
        user: str | None,
        pwd: str | None,
        use_tls: bool,
    ) -> None:
        """Synchronous SMTP delivery helper executed in worker thread."""
        with smtplib.SMTP(host=host, port=port, timeout=self.timeout_sec) as server:
            if use_tls:
                server.starttls()
            if user and pwd:
                server.login(user, pwd)
            server.send_message(msg)

    async def send_async(
        self,
        payload: NotificationPayloadDTO,
        config: TenantNotificationConfigDTO | None = None,
    ) -> ChannelDeliveryResultDTO:
        start_time = time.perf_counter()

        recipients = (
            (config.email_recipients if config and config.email_recipients else None)
            or self.default_recipients
        )

        if not recipients:
            return ChannelDeliveryResultDTO(
                channel=self.channel_type,
                status=DeliveryStatus.SKIPPED,
                latency_ms=(time.perf_counter() - start_time) * 1000.0,
                error="No target email recipients configured.",
            )

        smtp_host = (
            self.smtp_host
            or settings.get_secret("SMTP_HOST")
        )
        smtp_port = int(settings.get_secret("SMTP_PORT", self.smtp_port))
        smtp_user = self.smtp_user or settings.get_secret("SMTP_USER")
        smtp_pwd = self.smtp_password or settings.get_secret("SMTP_PASSWORD")
        smtp_from = settings.get_secret("SMTP_FROM", self.smtp_from)
        smtp_use_tls = bool(settings.get_secret("SMTP_USE_TLS", self.smtp_use_tls))

        msg = self._format_email_message(payload, recipients, smtp_from)

        # If SMTP host is configured, perform network delivery in thread
        if smtp_host:
            try:
                await asyncio.to_thread(
                    self._send_smtp_sync,
                    msg,
                    smtp_host,
                    smtp_port,
                    smtp_user,
                    smtp_pwd,
                    smtp_use_tls,
                )
                elapsed_ms = (time.perf_counter() - start_time) * 1000.0
                return ChannelDeliveryResultDTO(
                    channel=self.channel_type,
                    status=DeliveryStatus.DELIVERED,
                    latency_ms=elapsed_ms,
                    status_code=250,
                )
            except Exception as exc:
                elapsed_ms = (time.perf_counter() - start_time) * 1000.0
                logger.warning("SMTP email dispatch failed: %s", exc)
                return ChannelDeliveryResultDTO(
                    channel=self.channel_type,
                    status=DeliveryStatus.FAILED,
                    latency_ms=elapsed_ms,
                    error=str(exc),
                )
        else:
            # Simulated environment / dev fallback
            elapsed_ms = (time.perf_counter() - start_time) * 1000.0
            logger.info(
                "Simulated SMTP dispatch to %s. Subject: [%s] %s",
                ", ".join(recipients),
                payload.priority.value.upper(),
                payload.title,
            )
            return ChannelDeliveryResultDTO(
                channel=self.channel_type,
                status=DeliveryStatus.DELIVERED,
                latency_ms=elapsed_ms,
                status_code=250,
            )
