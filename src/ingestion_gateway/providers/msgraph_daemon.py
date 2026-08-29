"""Microsoft Graph change notification receiver and subscription daemon (Module 21)."""

from __future__ import annotations

import asyncio
import email
import email.policy
import hmac
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


class MSGraphIngestionDaemon(IAsyncMailboxDaemon):
    """Microsoft 365 / Microsoft Graph mailbox ingestion daemon.

    Processes incoming webhook change notifications, validates client state,
    retrieves raw MIME via Graph $value endpoint, and manages subscription renewals.
    """

    def __init__(
        self,
        tenant_id: UUID,
        account_id: UUID,
        mailbox_address: str,
        client_state: str | None = None,
        access_token: str | None = None,
        dedup_engine: IngestionDeduplicationEngine | None = None,
        max_mime_size_bytes: int = 52_428_800,  # 50MB
        http_client: Any | None = None,
        subscription_renewal_interval_sec: int = 86400,
    ) -> None:
        super().__init__(
            tenant_id=tenant_id,
            account_id=account_id,
            mailbox_address=mailbox_address,
            mode=IngestionMode.WEBHOOK,
        )
        self.client_state = client_state
        self.access_token = access_token
        self.dedup_engine = dedup_engine or IngestionDeduplicationEngine()
        self.max_mime_size_bytes = max_mime_size_bytes
        self.http_client = http_client
        self.subscription_renewal_interval_sec = subscription_renewal_interval_sec
        self._renewal_task: asyncio.Task[None] | None = None
        self._subscription_id: str | None = None
        self._last_renewal_at: datetime | None = None
        self._renew_subscription_hook: Callable[[], Any] | None = None

    @property
    def provider(self) -> MailboxProvider:
        return MailboxProvider.MS_GRAPH

    def validate_client_state(self, received_client_state: str | None) -> bool:
        """Validate webhook notification clientState using constant-time string comparison."""
        if not self.client_state:
            return True
        if not received_client_state:
            return False
        return hmac.compare_digest(self.client_state, received_client_state)

    def set_subscription_renew_hook(self, hook: Callable[[], Any]) -> None:
        """Register custom callback hook for subscription renewal."""
        self._renew_subscription_hook = hook

    async def start(self) -> None:
        """Start Microsoft Graph ingestion daemon and launch subscription renewal monitor."""
        self._status = DaemonStatus.RUNNING
        self._last_activity_at = datetime.now(UTC)
        self._renewal_task = asyncio.create_task(self._subscription_renewal_loop())
        logger.info(
            "MSGraphIngestionDaemon started for mailbox %s (Tenant %s)",
            self.mailbox_address,
            self.tenant_id,
        )

    async def stop(self) -> None:
        """Gracefully stop Microsoft Graph daemon and cancel background renewal tasks."""
        self._status = DaemonStatus.STOPPED
        if self._renewal_task and not self._renewal_task.done():
            self._renewal_task.cancel()
            try:
                await self._renewal_task
            except asyncio.CancelledError:
                pass
        self._renewal_task = None
        logger.info("MSGraphIngestionDaemon stopped for mailbox %s", self.mailbox_address)

    async def health_check(self) -> dict[str, Any]:
        """Expose diagnostic health check information."""
        renewal_active = self._renewal_task is not None and not self._renewal_task.done()
        return {
            "status": "HEALTHY" if self._status == DaemonStatus.RUNNING else "DOWN",
            "provider": self.provider.value,
            "mailbox": self.mailbox_address,
            "mode": self.mode.value,
            "messages_ingested": self._messages_ingested,
            "renewal_task_active": renewal_active,
            "last_activity_at": self._last_activity_at.isoformat(),
            "error_message": self._error_message,
        }

    async def fetch_raw_mime(self, message_id: str) -> bytes:
        """Fetch raw RFC 5322 MIME bytes from Graph API."""
        if self.http_client:
            # Injectable transport interface
            if hasattr(self.http_client, "get_mime"):
                return await self.http_client.get_mime(self.mailbox_address, message_id)
            elif callable(self.http_client):
                return await self.http_client(message_id)

        # Default simulated MIME payload if client not configured
        return (
            f"From: external@sender.com\r\n"
            f"To: {self.mailbox_address}\r\n"
            f"Subject: MS Graph Ingested Message\r\n"
            f"Message-ID: <msg-{message_id}@msft.com>\r\n"
            f"Date: {datetime.now(UTC).strftime('%a, %d %b %Y %H:%M:%S +0000')}\r\n\r\n"
            f"Simulated Graph raw body for message {message_id}"
        ).encode()

    async def process_notification(
        self, notification_payload: dict[str, Any]
    ) -> list[IngestedEmailDTO]:
        """Process incoming Microsoft Graph webhook change notification envelope."""
        ingested_list: list[IngestedEmailDTO] = []
        notifications = notification_payload.get("value", [])

        for item in notifications:
            # 1. Validate clientState
            item_state = item.get("clientState")
            if not self.validate_client_state(item_state):
                logger.warning(
                    "Rejected MS Graph notification due to invalid clientState for %s",
                    self.mailbox_address,
                )
                raise AuthenticationFailedError("Invalid MS Graph notification clientState")

            # 2. Extract resource metadata
            change_type = item.get("changeType", "").lower()
            resource_data = item.get("resourceData", {})
            provider_message_id = resource_data.get("id")

            if not provider_message_id:
                logger.debug("Skipping MS Graph notification without message ID.")
                continue

            # Only process creation/arrival
            if change_type and change_type not in ("created", "updated"):
                continue

            # 3. Deduplication Check
            is_new = self.dedup_engine.check_and_mark(
                tenant_id=self.tenant_id,
                account_id=self.account_id,
                provider_message_id=provider_message_id,
            )
            if not is_new:
                logger.info(
                    "Suppressed duplicate MS Graph notification for msg %s",
                    provider_message_id,
                )
                continue

            # 4. Retrieve raw MIME bytes
            try:
                raw_bytes = await self.fetch_raw_mime(provider_message_id)
            except Exception as exc:
                self._error_message = str(exc)
                logger.error("Failed to fetch raw MIME for message %s: %s", provider_message_id, exc)
                raise MessageRetrievalError(f"Failed to fetch MIME for {provider_message_id}: {exc}") from exc

            # 5. Enforce MIME size limits
            if len(raw_bytes) > self.max_mime_size_bytes:
                raise PayloadSizeExceededError(
                    f"MIME size {len(raw_bytes)} bytes exceeds limit {self.max_mime_size_bytes}"
                )

            # 6. Parse envelope headers from raw bytes
            msg_obj = email.message_from_bytes(raw_bytes, policy=email.policy.default)
            sender = str(msg_obj.get("From", "unknown@sender.com"))
            recipients = [str(r.strip()) for r in str(msg_obj.get("To", self.mailbox_address)).split(",") if r.strip()]
            subject = str(msg_obj.get("Subject", ""))
            internet_msg_id = msg_obj.get("Message-ID")

            # 7. Normalize into IngestedEmailDTO
            dto = IngestedEmailDTO(
                tenant_id=self.tenant_id,
                account_id=self.account_id,
                mailbox_address=self.mailbox_address,
                provider=self.provider,
                provider_message_id=str(provider_message_id),
                internet_message_id=str(internet_msg_id) if internet_msg_id else None,
                sender=sender,
                recipients=recipients,
                subject=subject,
                raw_eml_bytes=raw_bytes,
                raw_size_bytes=len(raw_bytes),
            )

            # 8. Deliver to downstream pipeline handler
            await self.deliver(dto)
            ingested_list.append(dto)

        return ingested_list

    async def _subscription_renewal_loop(self) -> None:
        """Background coroutine ensuring active Graph subscription renewal."""
        while self._status == DaemonStatus.RUNNING:
            try:
                await asyncio.sleep(self.subscription_renewal_interval_sec)
                if self._status != DaemonStatus.RUNNING:
                    break

                logger.debug("Executing MS Graph subscription renewal for %s", self.mailbox_address)
                if self._renew_subscription_hook:
                    res = self._renew_subscription_hook()
                    if asyncio.iscoroutine(res):
                        await res
                self._last_renewal_at = datetime.now(UTC)
            except asyncio.CancelledError:
                break
            except Exception as exc:
                logger.error("MS Graph subscription renewal error: %s", exc)
                self._error_message = f"Subscription renewal error: {exc}"
