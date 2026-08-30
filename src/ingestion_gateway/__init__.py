"""Enterprise Live Mailbox Ingestion Gateway & Webhook Daemon Package (Modules 21 & 22)."""

from __future__ import annotations

from src.ingestion_gateway.coordinator import AccountSyncCoordinator
from src.ingestion_gateway.dead_letter import (
    DeadLetterItemDTO,
    DeadLetterQueue,
)
from src.ingestion_gateway.dedup import IngestionDeduplicationEngine
from src.ingestion_gateway.exceptions import (
    AuthenticationFailedError,
    DaemonLifecycleError,
    DeadLetterError,
    DuplicateMessageSuppressedError,
    IngestionGatewayError,
    MessageRetrievalError,
    PayloadSizeExceededError,
    ProviderConnectionError,
)
from src.ingestion_gateway.manager import IngestionGatewayManager
from src.ingestion_gateway.models import (
    DaemonStatus,
    IngestedEmailDTO,
    IngestionDedupRecordDTO,
    IngestionMode,
    MailboxDaemonStateDTO,
    MailboxProvider,
)
from src.ingestion_gateway.module import (
    IngestionGatewayModule,
    register_ingestion_gateway_module,
)
from src.ingestion_gateway.persistence import (
    FileBackedDeadLetterStorage,
    IDeadLetterStorage,
    InMemoryDeadLetterStorage,
)
from src.ingestion_gateway.providers.base import (
    DeliveryHandler,
    IAsyncMailboxDaemon,
)
from src.ingestion_gateway.providers.gmail_daemon import GmailIngestionDaemon
from src.ingestion_gateway.providers.imap_daemon import IMAPIngestionDaemon
from src.ingestion_gateway.providers.msgraph_daemon import MSGraphIngestionDaemon
from src.ingestion_gateway.redis_dedup import RedisIngestionDeduplicationEngine
from src.ingestion_gateway.webhook_handler import (
    MailboxDaemonRegistry,
    get_daemon_registry,
    get_dead_letter_queue,
    ingestion_webhook_router,
)

__all__ = [
    # Enums
    "MailboxProvider",
    "DaemonStatus",
    "IngestionMode",
    # DTOs
    "IngestedEmailDTO",
    "MailboxDaemonStateDTO",
    "IngestionDedupRecordDTO",
    "DeadLetterItemDTO",
    # Deduplication & Dead Letter Queue
    "IngestionDeduplicationEngine",
    "RedisIngestionDeduplicationEngine",
    "DeadLetterQueue",
    # Persistence Adapters (Module 22)
    "IDeadLetterStorage",
    "InMemoryDeadLetterStorage",
    "FileBackedDeadLetterStorage",
    # Coordinator & Manager (Module 22)
    "AccountSyncCoordinator",
    "IngestionGatewayManager",
    "IngestionGatewayModule",
    "register_ingestion_gateway_module",
    # Provider interfaces & daemons
    "IAsyncMailboxDaemon",
    "DeliveryHandler",
    "MSGraphIngestionDaemon",
    "GmailIngestionDaemon",
    "IMAPIngestionDaemon",
    # Webhook Router & Registry
    "MailboxDaemonRegistry",
    "ingestion_webhook_router",
    "get_daemon_registry",
    "get_dead_letter_queue",
    # Exceptions
    "IngestionGatewayError",
    "ProviderConnectionError",
    "AuthenticationFailedError",
    "MessageRetrievalError",
    "DuplicateMessageSuppressedError",
    "PayloadSizeExceededError",
    "DeadLetterError",
    "DaemonLifecycleError",
]
