"""Ingestion Gateway Manager coordinating daemons, pipeline handoff, and EventBus emission."""

from __future__ import annotations

import asyncio
from typing import Any
from uuid import UUID

from src.container.di import Container
from src.events.ingestion_events import (
    EmailDownloadedEvent,
    IngestionDeadLetteredEvent,
    MailboxConnectedEvent,
    MailboxDisconnectedEvent,
)
from src.ingestion_gateway.dead_letter import (
    DeadLetterItemDTO,
    DeadLetterQueue,
)
from src.ingestion_gateway.dedup import IngestionDeduplicationEngine
from src.ingestion_gateway.models import (
    DaemonStatus,
    IngestedEmailDTO,
    MailboxProvider,
)
from src.ingestion_gateway.providers.base import IAsyncMailboxDaemon
from src.ingestion_gateway.providers.gmail_daemon import GmailIngestionDaemon
from src.ingestion_gateway.providers.imap_daemon import IMAPIngestionDaemon
from src.ingestion_gateway.providers.msgraph_daemon import MSGraphIngestionDaemon
from src.ingestion_gateway.webhook_handler import (
    MailboxDaemonRegistry,
    get_daemon_registry,
    get_dead_letter_queue,
)
from src.interfaces.event_publisher import IEventPublisher
from src.utils.logging import get_logger

logger = get_logger(__name__)


class IngestionGatewayManager:
    """Central orchestrator for the Enterprise Live Mailbox Ingestion Gateway Subsystem."""

    def __init__(
        self,
        registry: MailboxDaemonRegistry | None = None,
        dedup_engine: IngestionDeduplicationEngine | None = None,
        dlq: DeadLetterQueue | None = None,
        event_publisher: IEventPublisher | None = None,
        orchestrator: Any | None = None,
        di_container: Container | None = None,
    ) -> None:
        self.registry = registry or get_daemon_registry()
        self.dedup_engine = dedup_engine or IngestionDeduplicationEngine()
        self.dlq = dlq or get_dead_letter_queue()
        self.event_publisher = event_publisher
        self.orchestrator = orchestrator
        self.container = di_container
        self._is_running = False

        # Configure DLQ event publishing hook
        self.dlq.set_event_hook(self._on_dead_letter_enqueued)

    def _on_dead_letter_enqueued(self, item: DeadLetterItemDTO) -> None:
        """Publish IngestionDeadLetteredEvent asynchronously to EventBus when a poison item is captured."""
        if not self.event_publisher:
            return

        try:
            evt = IngestionDeadLetteredEvent(
                tenant_id=item.tenant_id,
                account_id=item.account_id,
                dead_letter_id=item.dead_letter_id,
                provider=item.provider.value,
                reason=item.reason,
                provider_message_id=item.provider_message_id,
                error_message=item.error_message,
                correlation_id=item.correlation_id,
            )
            # Schedule publishing
            try:
                loop = asyncio.get_running_loop()
                loop.create_task(self.event_publisher.publish(evt))
            except RuntimeError:
                asyncio.run(self.event_publisher.publish(evt))
        except Exception as exc:
            logger.error("Failed to publish IngestionDeadLetteredEvent: %s", exc)

    def create_and_register_daemon(
        self,
        tenant_id: UUID,
        account_id: UUID,
        mailbox_address: str,
        provider: MailboxProvider,
        **kwargs: Any,
    ) -> IAsyncMailboxDaemon:
        """Instantiate and register a concrete mailbox daemon worker with default delivery routing."""
        daemon: IAsyncMailboxDaemon
        if provider == MailboxProvider.MS_GRAPH:
            daemon = MSGraphIngestionDaemon(
                tenant_id=tenant_id,
                account_id=account_id,
                mailbox_address=mailbox_address,
                dedup_engine=self.dedup_engine,
                **kwargs,
            )
        elif provider == MailboxProvider.GMAIL:
            daemon = GmailIngestionDaemon(
                tenant_id=tenant_id,
                account_id=account_id,
                mailbox_address=mailbox_address,
                dedup_engine=self.dedup_engine,
                **kwargs,
            )
        elif provider == MailboxProvider.IMAP:
            daemon = IMAPIngestionDaemon(
                tenant_id=tenant_id,
                account_id=account_id,
                mailbox_address=mailbox_address,
                dedup_engine=self.dedup_engine,
                **kwargs,
            )
        else:
            raise ValueError(f"Unsupported mailbox provider: {provider}")

        # Wire default pipeline delivery handler
        daemon.set_delivery_handler(self.handle_ingested_email)
        self.registry.register(daemon)
        return daemon

    async def handle_ingested_email(self, email_dto: IngestedEmailDTO) -> None:
        """Default delivery handler processing normalized emails, emitting events, and invoking pipeline."""
        logger.info(
            "Handling ingested email %s from %s (Tenant %s, Account %s)",
            email_dto.provider_message_id,
            email_dto.mailbox_address,
            email_dto.tenant_id,
            email_dto.account_id,
        )

        # 1. Publish EmailDownloadedEvent if publisher configured
        if self.event_publisher:
            try:
                downloaded_evt = EmailDownloadedEvent(
                    tenant_id=email_dto.tenant_id,
                    account_id=email_dto.account_id,
                    raw_email_id=email_dto.ingestion_id,
                    message_id=email_dto.provider_message_id,
                    internet_message_id=email_dto.internet_message_id or "",
                    sender_address=email_dto.sender,
                    recipient_addresses=email_dto.recipients,
                    subject=email_dto.subject,
                    received_at=email_dto.received_at,
                    raw_size_bytes=email_dto.raw_size_bytes,
                    correlation_id=email_dto.correlation_id,
                )
                await self.event_publisher.publish(downloaded_evt)
            except Exception as pub_exc:
                logger.warning("Failed to publish EmailDownloadedEvent: %s", pub_exc)

        # 2. Invoke Downstream EmailSecurityPipelineOrchestrator if available
        orchestrator = self.orchestrator
        if not orchestrator and self.container:
            try:
                from src.orchestrator.orchestrator import (
                    EmailSecurityPipelineOrchestrator,
                )

                if self.container.has(EmailSecurityPipelineOrchestrator):
                    orchestrator = self.container.resolve(EmailSecurityPipelineOrchestrator)
            except Exception:
                orchestrator = None

        if orchestrator:
            try:
                from src.orchestrator.models import PipelineContext

                raw_email_entity = email_dto.to_raw_email()
                context = PipelineContext(
                    tenant_id=email_dto.tenant_id,
                    correlation_id=str(email_dto.correlation_id),
                )
                logger.info(
                    "Piping ingested email %s to EmailSecurityPipelineOrchestrator...",
                    email_dto.provider_message_id,
                )
                await orchestrator.execute_pipeline(
                    raw_email=raw_email_entity,
                    context=context,
                )
            except Exception as orch_exc:
                logger.error(
                    "Error executing downstream pipeline for email %s: %s",
                    email_dto.provider_message_id,
                    orch_exc,
                )
                self.dlq.enqueue(
                    tenant_id=email_dto.tenant_id,
                    account_id=email_dto.account_id,
                    provider=email_dto.provider,
                    reason="PIPELINE_ORCHESTRATOR_FAILURE",
                    error_message=str(orch_exc),
                    provider_message_id=email_dto.provider_message_id,
                    correlation_id=email_dto.correlation_id,
                )
                raise

    async def start_all(self) -> None:
        """Start all registered mailbox daemons and emit MailboxConnectedEvents."""
        self._is_running = True
        daemons = self.registry.list_daemons()
        logger.info("Starting %d registered mailbox daemon(s)...", len(daemons))

        for daemon in daemons:
            if daemon.status != DaemonStatus.RUNNING:
                try:
                    await daemon.start()
                    if self.event_publisher:
                        await self.event_publisher.publish(
                            MailboxConnectedEvent(
                                tenant_id=daemon.tenant_id,
                                account_id=daemon.account_id,
                                mailbox_address=daemon.mailbox_address,
                                provider=daemon.provider.value,
                                mode=daemon.mode.value,
                            )
                        )
                except Exception as exc:
                    logger.error("Failed to start daemon for %s: %s", daemon.mailbox_address, exc)

    async def stop_all(self) -> None:
        """Stop all registered mailbox daemons and emit MailboxDisconnectedEvents."""
        self._is_running = False
        daemons = self.registry.list_daemons()
        logger.info("Stopping %d registered mailbox daemon(s)...", len(daemons))

        for daemon in daemons:
            if daemon.status == DaemonStatus.RUNNING:
                try:
                    await daemon.stop()
                    if self.event_publisher:
                        await self.event_publisher.publish(
                            MailboxDisconnectedEvent(
                                tenant_id=daemon.tenant_id,
                                account_id=daemon.account_id,
                                mailbox_address=daemon.mailbox_address,
                                provider=daemon.provider.value,
                                reason="MANAGER_SHUTDOWN",
                            )
                        )
                except Exception as exc:
                    logger.error("Failed to cleanly stop daemon for %s: %s", daemon.mailbox_address, exc)

    async def get_health_status(self) -> dict[str, Any]:
        """Aggregate health status across all registered daemons and dead-letter queue."""
        daemons = self.registry.list_daemons()
        daemon_health_list = []
        is_all_healthy = True

        for daemon in daemons:
            h = await daemon.health_check()
            daemon_health_list.append(h)
            if h.get("status") not in ("HEALTHY", "STOPPED"):
                is_all_healthy = False

        dlq_stats = self.dlq.get_stats()
        dedup_stats = self.dedup_engine.get_stats()

        return {
            "is_running": self._is_running,
            "overall_status": "HEALTHY" if is_all_healthy else "DEGRADED",
            "registered_daemons_count": len(daemons),
            "daemons": daemon_health_list,
            "dead_letter_queue": dlq_stats,
            "deduplication": dedup_stats,
        }
