"""Google Workspace / Gmail Pub/Sub push notification receiver and daemon (Module 21)."""

from __future__ import annotations

import asyncio
import base64
import email
import email.policy
import json
from collections.abc import Callable
from datetime import UTC, datetime
from typing import Any
from uuid import UUID

from src.ingestion_gateway.dedup import IngestionDeduplicationEngine
from src.ingestion_gateway.exceptions import (
    AuthenticationFailedError,
    MessageRetrievalError,
    PayloadSizeExceededError,
)
from src.ingestion_gateway.models import (
    DaemonStatus,
    IngestedEmailDTO,
    IngestionMode,
    MailboxProvider,
)
from src.ingestion_gateway.providers.base import IAsyncMailboxDaemon
from src.utils.logging import get_logger

logger = get_logger(__name__)


class GmailIngestionDaemon(IAsyncMailboxDaemon):
    """Google Workspace / Gmail mailbox ingestion daemon.

    Processes Google Cloud Pub/Sub push notifications, decodes Base64 message
    payloads, queries the Gmail History API for new message IDs, and fetches raw MIME.
    """

    def __init__(
        self,
        tenant_id: UUID,
        account_id: UUID,
        mailbox_address: str,
        access_token: str | None = None,
        verification_token: str | None = None,
        dedup_engine: IngestionDeduplicationEngine | None = None,
        max_mime_size_bytes: int = 52_428_800,  # 50MB
        api_client: Any | None = None,
        watch_renewal_interval_sec: int = 86400 * 6,  # 6 days (Gmail watch expires at 7 days)
    ) -> None:
        super().__init__(
            tenant_id=tenant_id,
            account_id=account_id,
            mailbox_address=mailbox_address,
            mode=IngestionMode.WEBHOOK,
        )
        self.access_token = access_token
        self.verification_token = verification_token
        self.dedup_engine = dedup_engine or IngestionDeduplicationEngine()
        self.max_mime_size_bytes = max_mime_size_bytes
        self.api_client = api_client
        self.watch_renewal_interval_sec = watch_renewal_interval_sec
        self._watch_renewal_task: asyncio.Task[None] | None = None
        self._last_history_id: int | None = None
        self._last_watch_renewal_at: datetime | None = None
        self._watch_renewal_hook: Callable[[], Any] | None = None

    @property
    def provider(self) -> MailboxProvider:
        return MailboxProvider.GMAIL

    def set_watch_renew_hook(self, hook: Callable[[], Any]) -> None:
        """Register custom callback hook for Gmail watch renewal."""
        self._watch_renewal_hook = hook

    async def start(self) -> None:
        """Start Gmail daemon and launch watch renewal monitor."""
        self._status = DaemonStatus.RUNNING
        self._last_activity_at = datetime.now(UTC)
        self._watch_renewal_task = asyncio.create_task(self._watch_renewal_loop())
        logger.info(
            "GmailIngestionDaemon started for mailbox %s (Tenant %s)",
            self.mailbox_address,
            self.tenant_id,
        )

    async def stop(self) -> None:
        """Gracefully stop Gmail daemon and cancel renewal background tasks."""
        self._status = DaemonStatus.STOPPED
        if self._watch_renewal_task and not self._watch_renewal_task.done():
            self._watch_renewal_task.cancel()
            try:
                await self._watch_renewal_task
            except asyncio.CancelledError:
                pass
        self._watch_renewal_task = None
        logger.info("GmailIngestionDaemon stopped for mailbox %s", self.mailbox_address)

    async def health_check(self) -> dict[str, Any]:
        """Expose diagnostic health check information."""
        watch_active = self._watch_renewal_task is not None and not self._watch_renewal_task.done()
        return {
            "status": "HEALTHY" if self._status == DaemonStatus.RUNNING else "DOWN",
            "provider": self.provider.value,
            "mailbox": self.mailbox_address,
            "mode": self.mode.value,
            "messages_ingested": self._messages_ingested,
            "watch_renewal_active": watch_active,
            "last_history_id": self._last_history_id,
            "last_activity_at": self._last_activity_at.isoformat(),
            "error_message": self._error_message,
        }

    async def fetch_raw_mime(self, message_id: str) -> bytes:
        """Fetch raw RFC 5322 MIME bytes from Gmail API."""
        if self.api_client:
            if hasattr(self.api_client, "get_raw_mime"):
                return await self.api_client.get_raw_mime(message_id)
            elif callable(self.api_client):
                return await self.api_client(message_id)

        # Default simulated MIME payload if client not configured
        return (
            f"From: external@gmailsender.com\r\n"
            f"To: {self.mailbox_address}\r\n"
            f"Subject: Gmail Ingested Message\r\n"
            f"Message-ID: <msg-{message_id}@gmail.com>\r\n"
            f"Date: {datetime.now(UTC).strftime('%a, %d %b %Y %H:%M:%S +0000')}\r\n\r\n"
            f"Simulated Gmail raw body for message {message_id}"
        ).encode()

    async def process_pubsub_envelope(
        self, envelope: dict[str, Any]
    ) -> list[IngestedEmailDTO]:
        """Process incoming Google Cloud Pub/Sub push notification envelope."""
        # 1. Validate envelope structure
        message_data = envelope.get("message")
        if not message_data or not isinstance(message_data, dict):
            raise MessageRetrievalError("Malformed Pub/Sub envelope: missing message object")

        encoded_data = message_data.get("data")
        if not encoded_data:
            raise MessageRetrievalError("Malformed Pub/Sub envelope: missing base64 data field")

        # 2. Base64 decode notification payload
        try:
            raw_json = base64.b64decode(encoded_data).decode("utf-8")
            payload = json.loads(raw_json)
        except Exception as exc:
            raise MessageRetrievalError(f"Failed to decode Pub/Sub data payload: {exc}") from exc

        email_address = payload.get("emailAddress")
        history_id = payload.get("historyId")

        # 3. Validate mailbox address matches
        if email_address and email_address.lower() != self.mailbox_address.lower():
            logger.warning(
                "Pub/Sub notification emailAddress '%s' does not match daemon mailbox '%s'",
                email_address,
                self.mailbox_address,
            )
            return []

        if history_id:
            try:
                self._last_history_id = int(history_id)
            except (ValueError, TypeError):
                pass

        # 4. Resolve message IDs to retrieve
        msg_ids: list[str] = []
        if self.api_client and hasattr(self.api_client, "list_history_messages"):
            msg_ids = await self.api_client.list_history_messages(self.mailbox_address, self._last_history_id)
        elif "messageId" in payload:
            msg_ids = [str(payload["messageId"])]
        elif message_data.get("messageId"):
            # Fallback to Pub/Sub message ID as synthetic seed
            msg_ids = [f"gmail_msg_{message_data['messageId']}"]

        ingested_list: list[IngestedEmailDTO] = []

        for provider_msg_id in msg_ids:
            # 5. Deduplication check
            is_new = self.dedup_engine.check_and_mark(
                tenant_id=self.tenant_id,
                account_id=self.account_id,
                provider_message_id=provider_msg_id,
            )
            if not is_new:
                logger.info("Suppressed duplicate Gmail message %s", provider_msg_id)
                continue

            # 6. Fetch raw MIME bytes
            try:
                raw_bytes = await self.fetch_raw_mime(provider_msg_id)
            except Exception as exc:
                self._error_message = str(exc)
                logger.error("Failed to retrieve raw MIME for Gmail message %s: %s", provider_msg_id, exc)
                raise MessageRetrievalError(f"Failed to retrieve Gmail MIME: {exc}") from exc

            # 7. Check size limits
            if len(raw_bytes) > self.max_mime_size_bytes:
                raise PayloadSizeExceededError(
                    f"Gmail MIME size {len(raw_bytes)} bytes exceeds limit {self.max_mime_size_bytes}"
                )

            # 8. Parse envelope
            msg_obj = email.message_from_bytes(raw_bytes, policy=email.policy.default)
            sender = str(msg_obj.get("From", "unknown@sender.com"))
            recipients = [str(r.strip()) for r in str(msg_obj.get("To", self.mailbox_address)).split(",") if r.strip()]
            subject = str(msg_obj.get("Subject", ""))
            internet_msg_id = msg_obj.get("Message-ID")

            # 9. Normalize
            dto = IngestedEmailDTO(
                tenant_id=self.tenant_id,
                account_id=self.account_id,
                mailbox_address=self.mailbox_address,
                provider=self.provider,
                provider_message_id=str(provider_msg_id),
                internet_message_id=str(internet_msg_id) if internet_msg_id else None,
                sender=sender,
                recipients=recipients,
                subject=subject,
                raw_eml_bytes=raw_bytes,
                raw_size_bytes=len(raw_bytes),
            )

            # 10. Deliver
            await self.deliver(dto)
            ingested_list.append(dto)

        return ingested_list

    async def _watch_renewal_loop(self) -> None:
        """Background loop ensuring Gmail watch subscription is renewed periodically."""
        while self._status == DaemonStatus.RUNNING:
            try:
                await asyncio.sleep(self.watch_renewal_interval_sec)
                if self._status != DaemonStatus.RUNNING:
                    break

                logger.debug("Executing Gmail watch renewal for %s", self.mailbox_address)
                if self._watch_renewal_hook:
                    res = self._watch_renewal_hook()
                    if asyncio.iscoroutine(res):
                        await res
                self._last_watch_renewal_at = datetime.now(UTC)
            except asyncio.CancelledError:
                break
            except Exception as exc:
                logger.error("Gmail watch renewal error: %s", exc)
                self._error_message = f"Watch renewal error: {exc}"
