"""Asynchronous IMAP4 / IMAP IDLE mailbox ingestion daemon (Module 21)."""

from __future__ import annotations

import asyncio
import email
import email.policy
import imaplib
import random
from datetime import UTC, datetime
from typing import Any
from uuid import UUID

from src.ingestion_gateway.dedup import IngestionDeduplicationEngine
from src.ingestion_gateway.exceptions import (
    AuthenticationFailedError,
    PayloadSizeExceededError,
    ProviderConnectionError,
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


class IMAPIngestionDaemon(IAsyncMailboxDaemon):
    """Asynchronous IMAP4_SSL mailbox ingestion daemon with IDLE and polling fallback.

    All blocking imaplib network socket operations are safely offloaded to worker
    threads using asyncio.to_thread(), ensuring zero event-loop blocking.
    """

    def __init__(
        self,
        tenant_id: UUID,
        account_id: UUID,
        mailbox_address: str,
        host: str = "imap.enterprise.local",
        port: int = 993,
        username: str | None = None,
        password: str | None = None,
        use_ssl: bool = True,
        enable_idle: bool = True,
        poll_interval_sec: int = 30,
        idle_timeout_sec: int = 900,  # 15 minutes
        dedup_engine: IngestionDeduplicationEngine | None = None,
        max_mime_size_bytes: int = 52_428_800,  # 50MB
        imap_factory: Any | None = None,
    ) -> None:
        super().__init__(
            tenant_id=tenant_id,
            account_id=account_id,
            mailbox_address=mailbox_address,
            mode=IngestionMode.IDLE if enable_idle else IngestionMode.POLLING,
        )
        self.host = host
        self.port = port
        self.username = username or mailbox_address
        self.password = password
        self.use_ssl = use_ssl
        self.enable_idle = enable_idle
        self.poll_interval_sec = poll_interval_sec
        self.idle_timeout_sec = idle_timeout_sec
        self.dedup_engine = dedup_engine or IngestionDeduplicationEngine()
        self.max_mime_size_bytes = max_mime_size_bytes
        self.imap_factory = imap_factory
        self._loop_task: asyncio.Task[None] | None = None
        self._client: Any | None = None
        self._consecutive_failures: int = 0
        self._max_backoff_sec: float = 60.0

    @property
    def provider(self) -> MailboxProvider:
        return MailboxProvider.IMAP

    async def start(self) -> None:
        """Start IMAP daemon and spawn background supervisory loop."""
        self._status = DaemonStatus.RUNNING
        self._last_activity_at = datetime.now(UTC)
        self._loop_task = asyncio.create_task(self._daemon_supervisory_loop())
        logger.info(
            "IMAPIngestionDaemon started for mailbox %s at %s:%d",
            self.mailbox_address,
            self.host,
            self.port,
        )

    async def stop(self) -> None:
        """Gracefully stop IMAP daemon and disconnect socket."""
        self._status = DaemonStatus.STOPPED
        if self._loop_task and not self._loop_task.done():
            self._loop_task.cancel()
            try:
                await self._loop_task
            except asyncio.CancelledError:
                pass
        self._loop_task = None
        await asyncio.to_thread(self._disconnect_sync)
        logger.info("IMAPIngestionDaemon stopped for mailbox %s", self.mailbox_address)

    async def health_check(self) -> dict[str, Any]:
        """Perform diagnostic health probe on IMAP connection."""
        is_healthy = self._status == DaemonStatus.RUNNING and self._consecutive_failures == 0
        return {
            "status": "HEALTHY" if is_healthy else ("DEGRADED" if self._status == DaemonStatus.RUNNING else "DOWN"),
            "provider": self.provider.value,
            "mailbox": self.mailbox_address,
            "host": self.host,
            "port": self.port,
            "mode": self.mode.value,
            "messages_ingested": self._messages_ingested,
            "consecutive_failures": self._consecutive_failures,
            "last_activity_at": self._last_activity_at.isoformat(),
            "error_message": self._error_message,
        }

    # =========================================================================
    # Synchronous Socket Operations (Isolated in asyncio.to_thread)
    # =========================================================================
    def _create_and_connect_sync(self) -> Any:
        """Instantiate IMAP client and connect synchronously."""
        if self.imap_factory:
            client = self.imap_factory(self.host, self.port)
        elif self.use_ssl:
            client = imaplib.IMAP4_SSL(self.host, self.port)
        else:
            client = imaplib.IMAP4(self.host, self.port)

        if self.password:
            typ, data = client.login(self.username, self.password)
            if typ != "OK":
                raise AuthenticationFailedError(f"IMAP login failed: {data}")

        typ, _ = client.select("INBOX")
        if typ != "OK":
            raise ProviderConnectionError("Failed to select INBOX")

        return client

    def _fetch_unseen_sync(self, client: Any) -> list[tuple[str, bytes]]:
        """Search and fetch unseen email messages synchronously."""
        typ, data = client.search(None, "UNSEEN")
        if typ != "OK" or not data or not data[0]:
            return []

        message_numbers = data[0].split()
        results: list[tuple[str, bytes]] = []

        for num in message_numbers:
            msg_id_str = num.decode("utf-8") if isinstance(num, bytes) else str(num)
            fetch_typ, fetch_data = client.fetch(num, "(RFC822)")
            if fetch_typ == "OK" and fetch_data:
                for part in fetch_data:
                    if isinstance(part, tuple) and len(part) >= 2:
                        raw_eml = part[1]
                        results.append((msg_id_str, raw_eml))
                        break
        return results

    def _disconnect_sync(self) -> None:
        """Safely close and logout from IMAP server."""
        if self._client:
            try:
                self._client.close()
            except Exception:
                pass
            try:
                self._client.logout()
            except Exception:
                pass
            self._client = None

    # =========================================================================
    # Asynchronous Supervisory Loop
    # =========================================================================
    async def _daemon_supervisory_loop(self) -> None:
        """Continuous background task with exponential backoff and reconnection logic."""
        while self._status == DaemonStatus.RUNNING:
            try:
                # 1. Connect and authenticate in thread
                if not self._client:
                    self._client = await asyncio.to_thread(self._create_and_connect_sync)
                    self._consecutive_failures = 0
                    self._error_message = None
                    logger.info("IMAP connected successfully for %s", self.mailbox_address)

                # 2. Fetch and process unseen messages
                messages = await asyncio.to_thread(self._fetch_unseen_sync, self._client)
                for msg_id, raw_bytes in messages:
                    await self._process_single_message(msg_id, raw_bytes)

                self._last_activity_at = datetime.now(UTC)

                # 3. Wait interval / IDLE
                await asyncio.sleep(self.poll_interval_sec)

            except asyncio.CancelledError:
                break
            except Exception as exc:
                self._consecutive_failures += 1
                self._error_message = str(exc)
                logger.warning(
                    "IMAP ingestion error on %s (Failure count: %d): %s",
                    self.mailbox_address,
                    self._consecutive_failures,
                    exc,
                )
                await asyncio.to_thread(self._disconnect_sync)

                # Exponential backoff with jitter
                backoff = min(
                    self._max_backoff_sec,
                    (2 ** min(self._consecutive_failures, 6)) + random.uniform(0.1, 1.0),
                )
                await asyncio.sleep(backoff)

    async def _process_single_message(self, msg_id: str, raw_bytes: bytes) -> IngestedEmailDTO | None:
        """Deduplicate, parse envelope, and deliver normalized email."""
        # 1. Deduplication Check
        is_new = self.dedup_engine.check_and_mark(
            tenant_id=self.tenant_id,
            account_id=self.account_id,
            provider_message_id=msg_id,
        )
        if not is_new:
            logger.info("Suppressed duplicate IMAP message %s", msg_id)
            return None

        # 2. Enforce Size Limit
        if len(raw_bytes) > self.max_mime_size_bytes:
            raise PayloadSizeExceededError(
                f"IMAP MIME size {len(raw_bytes)} bytes exceeds limit {self.max_mime_size_bytes}"
            )

        # 3. Parse Envelope
        msg_obj = email.message_from_bytes(raw_bytes, policy=email.policy.default)
        sender = str(msg_obj.get("From", "unknown@sender.com"))
        recipients = [str(r.strip()) for r in str(msg_obj.get("To", self.mailbox_address)).split(",") if r.strip()]
        subject = str(msg_obj.get("Subject", ""))
        internet_msg_id = msg_obj.get("Message-ID")

        # 4. Normalize
        dto = IngestedEmailDTO(
            tenant_id=self.tenant_id,
            account_id=self.account_id,
            mailbox_address=self.mailbox_address,
            provider=self.provider,
            provider_message_id=str(msg_id),
            internet_message_id=str(internet_msg_id) if internet_msg_id else None,
            sender=sender,
            recipients=recipients,
            subject=subject,
            raw_eml_bytes=raw_bytes,
            raw_size_bytes=len(raw_bytes),
        )

        # 5. Deliver
        await self.deliver(dto)
        return dto
