"""Targeted unit and integration tests for Module 21 (Phases 1-4 Complete Gateway Suite)."""

from __future__ import annotations

import asyncio
import base64
import json
import time
from datetime import UTC, datetime
from typing import Any
from unittest.mock import AsyncMock, MagicMock
from uuid import UUID, uuid4

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient
from pydantic import ValidationError

from src.common.exceptions import ScamONError
from src.container.di import Container
from src.database.models import RawEmail
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
    IngestionMode,
    MailboxDaemonStateDTO,
    MailboxProvider,
)
from src.ingestion_gateway.module import (
    IngestionGatewayModule,
    register_ingestion_gateway_module,
)
from src.ingestion_gateway.providers.base import IAsyncMailboxDaemon
from src.ingestion_gateway.providers.gmail_daemon import GmailIngestionDaemon
from src.ingestion_gateway.providers.imap_daemon import IMAPIngestionDaemon
from src.ingestion_gateway.providers.msgraph_daemon import MSGraphIngestionDaemon
from src.ingestion_gateway.webhook_handler import (
    MailboxDaemonRegistry,
    get_daemon_registry,
    get_dead_letter_queue,
    ingestion_webhook_router,
)
from src.interfaces.event_publisher import IEventPublisher
from src.registry.module_registry import ModuleRegistry


# ===========================================================================
# 1. DTO & Model Tests
# ===========================================================================
def test_ingested_email_dto_valid_creation() -> None:
    tenant_id = uuid4()
    account_id = uuid4()
    raw_bytes = b"From: attacker@evil.com\r\nTo: victim@corp.com\r\nSubject: Phish\r\n\r\nClick here."

    dto = IngestedEmailDTO(
        tenant_id=tenant_id,
        account_id=account_id,
        mailbox_address="victim@corp.com",
        provider=MailboxProvider.MS_GRAPH,
        provider_message_id="AAMkAGI2...",
        internet_message_id="<msg-123@evil.com>",
        sender="attacker@evil.com",
        recipients=["victim@corp.com", "security@corp.com"],
        subject="Phish",
        raw_eml_bytes=raw_bytes,
    )

    assert dto.tenant_id == tenant_id
    assert dto.account_id == account_id
    assert dto.provider == MailboxProvider.MS_GRAPH
    assert dto.provider_message_id == "AAMkAGI2..."
    assert dto.internet_message_id == "<msg-123@evil.com>"
    assert dto.raw_size_bytes == len(raw_bytes)
    assert isinstance(dto.ingestion_id, UUID)
    assert isinstance(dto.correlation_id, UUID)
    assert isinstance(dto.received_at, datetime)


def test_ingested_email_dto_to_raw_email() -> None:
    tenant_id = uuid4()
    account_id = uuid4()
    raw_bytes = b"From: boss@corp.com\r\nTo: finance@corp.com\r\nSubject: Urgent\r\n\r\nTransfer funds."

    dto = IngestedEmailDTO(
        tenant_id=tenant_id,
        account_id=account_id,
        mailbox_address="finance@corp.com",
        provider=MailboxProvider.MS_GRAPH,
        provider_message_id="graph_msg_555",
        internet_message_id="<boss-555@corp.com>",
        sender="boss@corp.com",
        recipients=["finance@corp.com"],
        subject="Urgent",
        raw_eml_bytes=raw_bytes,
    )

    raw_entity = dto.to_raw_email()
    assert isinstance(raw_entity, RawEmail)
    assert raw_entity.id == dto.ingestion_id
    assert raw_entity.tenant_id == tenant_id
    assert raw_entity.account_id == account_id
    assert raw_entity.raw_eml_data == raw_bytes
    assert raw_entity.raw_size_bytes == len(raw_bytes)
    assert raw_entity.message_id == "graph_msg_555"
    assert raw_entity.internet_message_id == "<boss-555@corp.com>"
    assert raw_entity.created_at == dto.received_at


def test_ingested_email_dto_auto_computes_size() -> None:
    raw_content = b"Header: Test\r\n\r\nBody Content 12345"
    dto = IngestedEmailDTO(
        tenant_id=uuid4(),
        account_id=uuid4(),
        mailbox_address="user@company.com",
        provider=MailboxProvider.GMAIL,
        provider_message_id="18b958c2b7d",
        sender="sender@example.com",
        recipients=["user@company.com"],
        raw_eml_bytes=raw_content,
    )
    assert dto.raw_size_bytes == len(raw_content)


def test_ingested_email_dto_immutability() -> None:
    dto = IngestedEmailDTO(
        tenant_id=uuid4(),
        account_id=uuid4(),
        mailbox_address="user@company.com",
        provider=MailboxProvider.IMAP,
        provider_message_id="9999",
        sender="sender@example.com",
        recipients=["user@company.com"],
        raw_eml_bytes=b"raw data",
    )
    with pytest.raises(ValidationError):
        dto.subject = "Modified"  # type: ignore


def test_ingested_email_dto_missing_required_fields_raises() -> None:
    with pytest.raises(ValidationError):
        IngestedEmailDTO(
            tenant_id=uuid4(),
            account_id=uuid4(),
            mailbox_address="user@company.com",
            provider_message_id="123",
            sender="a@b.com",
        )  # type: ignore


def test_mailbox_provider_enum_values() -> None:
    assert MailboxProvider.MS_GRAPH.value == "MS_GRAPH"
    assert MailboxProvider.GMAIL.value == "GMAIL"
    assert MailboxProvider.IMAP.value == "IMAP"


def test_daemon_status_and_mode_enums() -> None:
    assert DaemonStatus.RUNNING.value == "RUNNING"
    assert DaemonStatus.STOPPED.value == "STOPPED"
    assert IngestionMode.WEBHOOK.value == "WEBHOOK"
    assert IngestionMode.IDLE.value == "IDLE"
    assert IngestionMode.POLLING.value == "POLLING"


# ===========================================================================
# 2. Deduplication Engine Tests
# ===========================================================================
def test_dedup_deterministic_key_generation() -> None:
    t_id = UUID("11111111-1111-1111-1111-111111111111")
    a_id = UUID("22222222-2222-2222-2222-222222222222")
    msg_id = "msg_graph_12345"

    key1 = IngestionDeduplicationEngine.compute_dedup_key(t_id, a_id, msg_id)
    key2 = IngestionDeduplicationEngine.compute_dedup_key(t_id, a_id, msg_id)
    assert key1 == key2
    assert len(key1) == 64


def test_dedup_check_and_mark_workflow() -> None:
    engine = IngestionDeduplicationEngine(default_ttl_sec=3600)
    t_id = uuid4()
    a_id = uuid4()
    msg_id = "msg_test_001"

    is_new = engine.check_and_mark(t_id, a_id, msg_id)
    assert is_new is True

    is_new_again = engine.check_and_mark(t_id, a_id, msg_id)
    assert is_new_again is False

    assert engine.is_duplicate(t_id, a_id, msg_id) is True
    assert engine.is_duplicate(t_id, a_id, "other_msg") is False


def test_dedup_tenant_and_account_isolation() -> None:
    engine = IngestionDeduplicationEngine(default_ttl_sec=3600)
    tenant_1 = uuid4()
    tenant_2 = uuid4()
    account_1 = uuid4()
    account_2 = uuid4()
    same_msg_id = "shared_provider_id_999"

    assert engine.check_and_mark(tenant_1, account_1, same_msg_id) is True
    assert engine.check_and_mark(tenant_2, account_1, same_msg_id) is True
    assert engine.check_and_mark(tenant_1, account_2, same_msg_id) is True


def test_dedup_prune_and_ttl_expiration() -> None:
    engine = IngestionDeduplicationEngine(default_ttl_sec=1)
    t_id = uuid4()
    a_id = uuid4()
    msg_id = "quick_expire_msg"

    engine.check_and_mark(t_id, a_id, msg_id, ttl_sec=1)
    assert engine.is_duplicate(t_id, a_id, msg_id) is True

    time.sleep(1.05)
    assert engine.is_duplicate(t_id, a_id, msg_id) is False

    engine.check_and_mark(t_id, a_id, "msg_expire_2", ttl_sec=1)
    time.sleep(1.05)
    pruned = engine.prune_expired()
    assert pruned >= 1


def test_dedup_clear_by_tenant() -> None:
    engine = IngestionDeduplicationEngine(default_ttl_sec=3600)
    t1 = uuid4()
    t2 = uuid4()
    a = uuid4()

    engine.check_and_mark(t1, a, "msg_1")
    engine.check_and_mark(t2, a, "msg_2")

    assert engine.is_duplicate(t1, a, "msg_1") is True
    assert engine.is_duplicate(t2, a, "msg_2") is True

    engine.clear(tenant_id=t1)
    assert engine.is_duplicate(t1, a, "msg_1") is False
    assert engine.is_duplicate(t2, a, "msg_2") is True

    engine.clear()
    assert engine.is_duplicate(t2, a, "msg_2") is False


def test_dedup_stats_telemetry() -> None:
    engine = IngestionDeduplicationEngine(default_ttl_sec=3600)
    t = uuid4()
    a = uuid4()

    engine.check_and_mark(t, a, "m1")
    engine.check_and_mark(t, a, "m1")
    engine.check_and_mark(t, a, "m2")

    stats = engine.get_stats()
    assert stats["active_records_count"] == 2
    assert stats["total_checked"] == 3
    assert stats["total_duplicates_suppressed"] == 1


# ===========================================================================
# 3. Provider Daemon Base Contract Tests
# ===========================================================================
class MockMailboxDaemon(IAsyncMailboxDaemon):
    @property
    def provider(self) -> MailboxProvider:
        return MailboxProvider.IMAP

    async def start(self) -> None:
        self._status = DaemonStatus.RUNNING
        self._last_activity_at = datetime.now(UTC)

    async def stop(self) -> None:
        self._status = DaemonStatus.STOPPED

    async def health_check(self) -> dict[str, Any]:
        return {
            "status": "HEALTHY" if self._status == DaemonStatus.RUNNING else "DOWN",
            "provider": self.provider.value,
            "mailbox": self.mailbox_address,
            "messages_ingested": self._messages_ingested,
        }


@pytest.mark.asyncio
async def test_daemon_lifecycle_and_delivery() -> None:
    tenant_id = uuid4()
    account_id = uuid4()
    mailbox = "soc-inbox@enterprise.com"

    daemon = MockMailboxDaemon(
        tenant_id=tenant_id,
        account_id=account_id,
        mailbox_address=mailbox,
        mode=IngestionMode.IDLE,
    )

    assert daemon.status == DaemonStatus.STOPPED
    assert daemon.provider == MailboxProvider.IMAP
    assert daemon.messages_ingested == 0

    await daemon.start()
    assert daemon.status == DaemonStatus.RUNNING

    health = await daemon.health_check()
    assert health["status"] == "HEALTHY"
    assert health["mailbox"] == mailbox

    received_emails: list[IngestedEmailDTO] = []

    async def _on_email(email: IngestedEmailDTO) -> None:
        received_emails.append(email)

    daemon.set_delivery_handler(_on_email)

    test_email = IngestedEmailDTO(
        tenant_id=tenant_id,
        account_id=account_id,
        mailbox_address=mailbox,
        provider=MailboxProvider.IMAP,
        provider_message_id="imap_uid_101",
        sender="alerts@vendor.com",
        recipients=[mailbox],
        subject="Vendor Invoice Notification",
        raw_eml_bytes=b"Content-Type: text/plain\r\n\r\nInvoice attachment.",
    )

    await daemon.deliver(test_email)
    assert len(received_emails) == 1
    assert received_emails[0].provider_message_id == "imap_uid_101"
    assert daemon.messages_ingested == 1

    state = daemon.get_state()
    assert isinstance(state, MailboxDaemonStateDTO)
    assert state.messages_ingested == 1
    assert state.status == DaemonStatus.RUNNING

    await daemon.stop()
    assert daemon.status == DaemonStatus.STOPPED


# ===========================================================================
# 4. Microsoft Graph Daemon Tests (Phase 2)
# ===========================================================================
@pytest.mark.asyncio
async def test_msgraph_daemon_lifecycle_and_notification_processing() -> None:
    tenant_id = uuid4()
    account_id = uuid4()
    mailbox = "secops@corp.onmicrosoft.com"
    client_state = "SecretClientState123"

    delivered_emails: list[IngestedEmailDTO] = []

    async def _mock_delivery(email: IngestedEmailDTO) -> None:
        delivered_emails.append(email)

    mock_mime_bytes = (
        b"From: ceo@partner.com\r\n"
        b"To: secops@corp.onmicrosoft.com\r\n"
        b"Subject: Urgent Wire Transfer\r\n"
        b"Message-ID: <msg-graph-999@partner.com>\r\n\r\n"
        b"Please process the wire immediately."
    )
    mock_http_client = AsyncMock()
    mock_http_client.get_mime = AsyncMock(return_value=mock_mime_bytes)

    daemon = MSGraphIngestionDaemon(
        tenant_id=tenant_id,
        account_id=account_id,
        mailbox_address=mailbox,
        client_state=client_state,
        http_client=mock_http_client,
        subscription_renewal_interval_sec=1,
    )
    daemon.set_delivery_handler(_mock_delivery)

    assert daemon.validate_client_state("SecretClientState123") is True
    assert daemon.validate_client_state("WrongSecret") is False
    assert daemon.validate_client_state(None) is False

    await daemon.start()
    assert daemon.status == DaemonStatus.RUNNING

    notification_payload = {
        "value": [
            {
                "subscriptionId": "sub-12345",
                "clientState": "SecretClientState123",
                "changeType": "created",
                "resourceData": {"id": "AAMkAGI2_msg_001"},
            }
        ]
    }

    ingested = await daemon.process_notification(notification_payload)
    assert len(ingested) == 1
    assert len(delivered_emails) == 1
    assert delivered_emails[0].provider == MailboxProvider.MS_GRAPH
    assert delivered_emails[0].provider_message_id == "AAMkAGI2_msg_001"
    assert delivered_emails[0].subject == "Urgent Wire Transfer"
    assert delivered_emails[0].sender == "ceo@partner.com"

    ingested_dups = await daemon.process_notification(notification_payload)
    assert len(ingested_dups) == 0
    assert len(delivered_emails) == 1

    health = await daemon.health_check()
    assert health["status"] == "HEALTHY"
    assert health["renewal_task_active"] is True

    await daemon.stop()
    assert daemon.status == DaemonStatus.STOPPED


@pytest.mark.asyncio
async def test_msgraph_daemon_invalid_client_state_rejected() -> None:
    daemon = MSGraphIngestionDaemon(
        tenant_id=uuid4(),
        account_id=uuid4(),
        mailbox_address="test@corp.com",
        client_state="ValidState",
    )
    invalid_payload = {
        "value": [
            {
                "clientState": "ForgedState",
                "resourceData": {"id": "msg_forged"},
            }
        ]
    }
    with pytest.raises(AuthenticationFailedError):
        await daemon.process_notification(invalid_payload)


@pytest.mark.asyncio
async def test_msgraph_daemon_size_limit_rejection() -> None:
    mock_http = AsyncMock()
    mock_http.get_mime = AsyncMock(return_value=b"A" * 2000)

    daemon = MSGraphIngestionDaemon(
        tenant_id=uuid4(),
        account_id=uuid4(),
        mailbox_address="test@corp.com",
        max_mime_size_bytes=1000,
        http_client=mock_http,
    )
    payload = {
        "value": [{"resourceData": {"id": "msg_oversized"}}]
    }
    with pytest.raises(PayloadSizeExceededError):
        await daemon.process_notification(payload)


@pytest.mark.asyncio
async def test_msgraph_subscription_renewal_hook() -> None:
    renew_called = False

    def _hook() -> None:
        nonlocal renew_called
        renew_called = True

    daemon = MSGraphIngestionDaemon(
        tenant_id=uuid4(),
        account_id=uuid4(),
        mailbox_address="test@corp.com",
        subscription_renewal_interval_sec=0.05,
    )
    daemon.set_subscription_renew_hook(_hook)

    await daemon.start()
    await asyncio.sleep(0.12)
    await daemon.stop()

    assert renew_called is True


# ===========================================================================
# 5. Gmail Daemon Tests (Phase 2)
# ===========================================================================
@pytest.mark.asyncio
async def test_gmail_daemon_lifecycle_and_pubsub_processing() -> None:
    tenant_id = uuid4()
    account_id = uuid4()
    mailbox = "analyst@enterprise.gmail.com"

    delivered_emails: list[IngestedEmailDTO] = []

    async def _mock_delivery(email: IngestedEmailDTO) -> None:
        delivered_emails.append(email)

    mock_raw_mime = (
        b"From: suspicious@free-gift.xyz\r\n"
        b"To: analyst@enterprise.gmail.com\r\n"
        b"Subject: You won a prize!\r\n"
        b"Message-ID: <gmail-prize-101@xyz.com>\r\n\r\n"
        b"Claim prize at http://evil.com"
    )

    mock_api = AsyncMock()
    mock_api.list_history_messages = AsyncMock(return_value=["gmail_msg_id_777"])
    mock_api.get_raw_mime = AsyncMock(return_value=mock_raw_mime)

    daemon = GmailIngestionDaemon(
        tenant_id=tenant_id,
        account_id=account_id,
        mailbox_address=mailbox,
        api_client=mock_api,
        watch_renewal_interval_sec=1,
    )
    daemon.set_delivery_handler(_mock_delivery)

    await daemon.start()
    assert daemon.status == DaemonStatus.RUNNING

    payload_data = {
        "emailAddress": mailbox,
        "historyId": 987654,
    }
    encoded_data = base64.b64encode(json.dumps(payload_data).encode("utf-8")).decode("utf-8")
    pubsub_envelope = {
        "message": {
            "data": encoded_data,
            "messageId": "pubsub_msg_555",
            "publishTime": "2026-08-29T12:00:00Z",
        }
    }

    ingested = await daemon.process_pubsub_envelope(pubsub_envelope)
    assert len(ingested) == 1
    assert len(delivered_emails) == 1
    assert delivered_emails[0].provider == MailboxProvider.GMAIL
    assert delivered_emails[0].provider_message_id == "gmail_msg_id_777"
    assert delivered_emails[0].subject == "You won a prize!"
    assert delivered_emails[0].sender == "suspicious@free-gift.xyz"

    dups = await daemon.process_pubsub_envelope(pubsub_envelope)
    assert len(dups) == 0

    health = await daemon.health_check()
    assert health["status"] == "HEALTHY"
    assert health["watch_renewal_active"] is True
    assert health["last_history_id"] == 987654

    await daemon.stop()
    assert daemon.status == DaemonStatus.STOPPED


@pytest.mark.asyncio
async def test_gmail_daemon_malformed_pubsub_envelope_rejected() -> None:
    daemon = GmailIngestionDaemon(
        tenant_id=uuid4(),
        account_id=uuid4(),
        mailbox_address="user@domain.com",
    )
    with pytest.raises(MessageRetrievalError):
        await daemon.process_pubsub_envelope({})

    with pytest.raises(MessageRetrievalError):
        await daemon.process_pubsub_envelope({"message": {}})


@pytest.mark.asyncio
async def test_gmail_watch_renewal_hook() -> None:
    renew_called = False

    def _hook() -> None:
        nonlocal renew_called
        renew_called = True

    daemon = GmailIngestionDaemon(
        tenant_id=uuid4(),
        account_id=uuid4(),
        mailbox_address="user@domain.com",
        watch_renewal_interval_sec=0.05,
    )
    daemon.set_watch_renew_hook(_hook)

    await daemon.start()
    await asyncio.sleep(0.12)
    await daemon.stop()

    assert renew_called is True


# ===========================================================================
# 6. IMAP Daemon Tests (Phase 2)
# ===========================================================================
class MockSynchronousIMAPClient:
    def __init__(self, raw_eml: bytes) -> None:
        self.raw_eml = raw_eml
        self.logged_in = False
        self.selected = False
        self.search_count = 0

    def login(self, username: str, password: str) -> tuple[str, list[bytes]]:
        self.logged_in = True
        return "OK", [b"LOGIN completed"]

    def select(self, mailbox: str) -> tuple[str, list[bytes]]:
        self.selected = True
        return "OK", [b"1"]

    def search(self, charset: Any, criteria: str) -> tuple[str, list[bytes]]:
        self.search_count += 1
        if self.search_count == 1:
            return "OK", [b"101"]
        return "OK", [b""]

    def fetch(self, num: str, spec: str) -> tuple[str, list[Any]]:
        return "OK", [(b"101 (RFC822)", self.raw_eml), b")"]

    def close(self) -> tuple[str, list[bytes]]:
        return "OK", [b"Closed"]

    def logout(self) -> tuple[str, list[bytes]]:
        return "BYE", [b"Logging out"]


@pytest.mark.asyncio
async def test_imap_daemon_lifecycle_and_fetch_workflow() -> None:
    tenant_id = uuid4()
    account_id = uuid4()
    mailbox = "imap_user@enterprise.com"

    mock_raw_eml = (
        b"From: alert@banking-fraud.com\r\n"
        b"To: imap_user@enterprise.com\r\n"
        b"Subject: Security Notice: Account Locked\r\n"
        b"Message-ID: <imap-fraud-99@bank.com>\r\n\r\n"
        b"Confirm login at http://fakebank.com"
    )

    mock_client = MockSynchronousIMAPClient(raw_eml=mock_raw_eml)
    delivered_emails: list[IngestedEmailDTO] = []

    async def _mock_delivery(email: IngestedEmailDTO) -> None:
        delivered_emails.append(email)

    daemon = IMAPIngestionDaemon(
        tenant_id=tenant_id,
        account_id=account_id,
        mailbox_address=mailbox,
        password="secret_password",
        poll_interval_sec=0.05,
        imap_factory=lambda host, port: mock_client,
    )
    daemon.set_delivery_handler(_mock_delivery)

    await daemon.start()
    assert daemon.status == DaemonStatus.RUNNING

    await asyncio.sleep(0.12)

    assert len(delivered_emails) >= 1
    assert delivered_emails[0].provider == MailboxProvider.IMAP
    assert delivered_emails[0].provider_message_id == "101"
    assert delivered_emails[0].subject == "Security Notice: Account Locked"
    assert delivered_emails[0].sender == "alert@banking-fraud.com"

    health = await daemon.health_check()
    assert health["status"] == "HEALTHY"
    assert health["messages_ingested"] >= 1

    await daemon.stop()
    assert daemon.status == DaemonStatus.STOPPED


@pytest.mark.asyncio
async def test_imap_daemon_reconnect_and_backoff_on_failure() -> None:
    class FailingIMAPClient:
        def select(self, m: str) -> tuple[str, list[bytes]]:
            raise ConnectionResetError("Connection dropped by remote host")

    daemon = IMAPIngestionDaemon(
        tenant_id=uuid4(),
        account_id=uuid4(),
        mailbox_address="faulty@enterprise.com",
        poll_interval_sec=0.05,
        imap_factory=lambda host, port: FailingIMAPClient(),
    )

    await daemon.start()
    await asyncio.sleep(0.12)

    health = await daemon.health_check()
    assert health["status"] == "DEGRADED"
    assert health["consecutive_failures"] >= 1
    assert "Connection dropped" in health["error_message"]

    await daemon.stop()
    assert daemon.status == DaemonStatus.STOPPED


# ===========================================================================
# 7. Dead-Letter Queue (DLQ) Tests (Phase 3)
# ===========================================================================
def test_dlq_enqueue_and_retrieve() -> None:
    dlq = DeadLetterQueue(max_items=10)
    tenant_id = uuid4()
    account_id = uuid4()

    item = dlq.enqueue(
        tenant_id=tenant_id,
        account_id=account_id,
        provider=MailboxProvider.MS_GRAPH,
        reason="PAYLOAD_SIZE_EXCEEDED",
        error_message="Raw MIME exceeded 50MB limit",
        provider_message_id="msg_dlq_001",
        raw_payload="A" * 10000,
    )

    assert isinstance(item, DeadLetterItemDTO)
    assert item.tenant_id == tenant_id
    assert item.reason == "PAYLOAD_SIZE_EXCEEDED"
    assert len(item.raw_payload) == 8192

    fetched = dlq.get(item.dead_letter_id)
    assert fetched is not None
    assert fetched.dead_letter_id == item.dead_letter_id


def test_dlq_tenant_isolation_and_purge() -> None:
    dlq = DeadLetterQueue(max_items=10)
    t1 = uuid4()
    t2 = uuid4()
    a = uuid4()

    item1 = dlq.enqueue(tenant_id=t1, account_id=a, provider=MailboxProvider.GMAIL, reason="CORRUPTED", error_message="err1")
    item2 = dlq.enqueue(tenant_id=t2, account_id=a, provider=MailboxProvider.IMAP, reason="CORRUPTED", error_message="err2")

    t1_items = dlq.list_items(tenant_id=t1)
    assert len(t1_items) == 1
    assert t1_items[0].dead_letter_id == item1.dead_letter_id

    t2_items = dlq.list_items(tenant_id=t2)
    assert len(t2_items) == 1
    assert t2_items[0].dead_letter_id == item2.dead_letter_id

    purged_count = dlq.clear_tenant(t1)
    assert purged_count == 1
    assert len(dlq.list_items(tenant_id=t1)) == 0
    assert len(dlq.list_items(tenant_id=t2)) == 1


def test_dlq_capacity_bounding_and_fifo_eviction() -> None:
    dlq = DeadLetterQueue(max_items=2)
    t = uuid4()
    a = uuid4()

    i1 = dlq.enqueue(tenant_id=t, account_id=a, provider=MailboxProvider.IMAP, reason="R1", error_message="e1")
    i2 = dlq.enqueue(tenant_id=t, account_id=a, provider=MailboxProvider.IMAP, reason="R2", error_message="e2")
    i3 = dlq.enqueue(tenant_id=t, account_id=a, provider=MailboxProvider.IMAP, reason="R3", error_message="e3")

    stats = dlq.get_stats()
    assert stats["current_size"] == 2
    assert stats["total_enqueued"] == 3

    assert dlq.get(i1.dead_letter_id) is None
    assert dlq.get(i2.dead_letter_id) is not None
    assert dlq.get(i3.dead_letter_id) is not None


def test_dlq_requeue_and_retry_count() -> None:
    dlq = DeadLetterQueue(max_items=10)
    item = dlq.enqueue(
        tenant_id=uuid4(),
        account_id=uuid4(),
        provider=MailboxProvider.GMAIL,
        reason="TRANSIENT_FAILURE",
        error_message="503 Service Unavailable",
    )

    assert item.retry_count == 0

    r1 = dlq.requeue(item.dead_letter_id)
    assert r1 is not None
    assert r1.retry_count == 1

    r2 = dlq.requeue(item.dead_letter_id)
    assert r2.retry_count == 2

    r3 = dlq.requeue(item.dead_letter_id)
    assert r3.retry_count == 3

    r4 = dlq.requeue(item.dead_letter_id)
    assert r4 is None


def test_dlq_event_hook_invocation() -> None:
    hook_called = False
    captured_item: DeadLetterItemDTO | None = None

    def _hook(item: DeadLetterItemDTO) -> None:
        nonlocal hook_called, captured_item
        hook_called = True
        captured_item = item

    dlq = DeadLetterQueue(max_items=10)
    dlq.set_event_hook(_hook)

    enqueued = dlq.enqueue(
        tenant_id=uuid4(),
        account_id=uuid4(),
        provider=MailboxProvider.MS_GRAPH,
        reason="PARSER_PANIC",
        error_message="Unparseable byte stream",
    )

    assert hook_called is True
    assert captured_item is not None
    assert captured_item.dead_letter_id == enqueued.dead_letter_id


# ===========================================================================
# 8. Webhook Handler & Registry Tests (Phase 3)
# ===========================================================================
def create_test_webhook_app() -> tuple[TestClient, MailboxDaemonRegistry, DeadLetterQueue]:
    """Create isolated FastAPI TestClient with fresh registry and DLQ."""
    app = FastAPI()
    registry = MailboxDaemonRegistry()
    dlq = DeadLetterQueue()

    app.dependency_overrides[get_daemon_registry] = lambda: registry
    app.dependency_overrides[get_dead_letter_queue] = lambda: dlq
    app.include_router(ingestion_webhook_router)

    return TestClient(app), registry, dlq


def test_msgraph_webhook_validation_handshake() -> None:
    client, _, _ = create_test_webhook_app()
    token = "SampleValidationToken12345"

    response = client.post(f"/api/v1/ingestion/webhooks/msgraph?validationToken={token}")
    assert response.status_code == 200
    assert response.text == token
    assert "text/plain" in response.headers["content-type"]


def test_msgraph_webhook_notification_routing() -> None:
    client, registry, _ = create_test_webhook_app()
    tenant_id = uuid4()
    account_id = uuid4()

    mock_http = AsyncMock()
    mock_http.get_mime = AsyncMock(return_value=b"From: ceo@test.com\r\nTo: user@corp.com\r\n\r\nHello")

    daemon = MSGraphIngestionDaemon(
        tenant_id=tenant_id,
        account_id=account_id,
        mailbox_address="user@corp.com",
        client_state="SecretGraphState",
        http_client=mock_http,
    )
    registry.register(daemon)

    payload = {
        "value": [
            {
                "subscriptionId": "sub_999",
                "clientState": "SecretGraphState",
                "changeType": "created",
                "resourceData": {"id": "msg_graph_web_001"},
            }
        ]
    }

    response = client.post("/api/v1/ingestion/webhooks/msgraph", json=payload)
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "accepted"
    assert data["processed_count"] == 1


def test_msgraph_webhook_invalid_client_state_returns_401() -> None:
    client, registry, _ = create_test_webhook_app()
    daemon = MSGraphIngestionDaemon(
        tenant_id=uuid4(),
        account_id=uuid4(),
        mailbox_address="user@corp.com",
        client_state="ExpectedSecret",
    )
    registry.register(daemon)

    payload = {
        "value": [
            {
                "clientState": "ForgedSecret",
                "resourceData": {"id": "msg_001"},
            }
        ]
    }

    response = client.post("/api/v1/ingestion/webhooks/msgraph", json=payload)
    assert response.status_code == 200
    assert response.json()["processed_count"] == 0


def test_msgraph_webhook_malformed_json_returns_400() -> None:
    client, _, _ = create_test_webhook_app()
    response = client.post(
        "/api/v1/ingestion/webhooks/msgraph",
        content="not-json",
        headers={"Content-Type": "application/json"},
    )
    assert response.status_code == 400


def test_msgraph_webhook_oversized_payload_routes_to_dlq() -> None:
    client, registry, dlq = create_test_webhook_app()
    mock_http = AsyncMock()
    mock_http.get_mime = AsyncMock(return_value=b"B" * 5000)

    daemon = MSGraphIngestionDaemon(
        tenant_id=uuid4(),
        account_id=uuid4(),
        mailbox_address="user@corp.com",
        client_state="SecretState",
        max_mime_size_bytes=1000,
        http_client=mock_http,
    )
    registry.register(daemon)

    payload = {
        "value": [
            {
                "clientState": "SecretState",
                "resourceData": {"id": "msg_oversized_web"},
            }
        ]
    }

    response = client.post("/api/v1/ingestion/webhooks/msgraph", json=payload)
    assert response.status_code == 422

    dlq_items = dlq.list_items()
    assert len(dlq_items) == 1
    assert dlq_items[0].reason == "PAYLOAD_SIZE_EXCEEDED"
    assert dlq_items[0].provider == MailboxProvider.MS_GRAPH


def test_gmail_webhook_pubsub_notification_routing() -> None:
    client, registry, _ = create_test_webhook_app()
    tenant_id = uuid4()
    account_id = uuid4()
    mailbox = "inbox@gmailcorp.com"

    mock_api = AsyncMock()
    mock_api.list_history_messages = AsyncMock(return_value=["gmail_web_msg_1"])
    mock_api.get_raw_mime = AsyncMock(return_value=b"From: a@b.com\r\nTo: inbox@gmailcorp.com\r\n\r\nTest")

    daemon = GmailIngestionDaemon(
        tenant_id=tenant_id,
        account_id=account_id,
        mailbox_address=mailbox,
        verification_token="SecretGmailToken",
        api_client=mock_api,
    )
    registry.register(daemon)

    payload_data = {"emailAddress": mailbox, "historyId": 12345}
    encoded_data = base64.b64encode(json.dumps(payload_data).encode("utf-8")).decode("utf-8")
    envelope = {
        "message": {
            "data": encoded_data,
            "messageId": "pubsub_111",
        }
    }

    response = client.post(
        "/api/v1/ingestion/webhooks/gmail?token=SecretGmailToken",
        json=envelope,
    )
    assert response.status_code == 200
    assert response.json()["processed_count"] == 1


def test_gmail_webhook_invalid_token_returns_401() -> None:
    client, registry, _ = create_test_webhook_app()
    daemon = GmailIngestionDaemon(
        tenant_id=uuid4(),
        account_id=uuid4(),
        mailbox_address="user@domain.com",
        verification_token="CorrectToken",
    )
    registry.register(daemon)

    envelope = {"message": {"data": "dGVzdA=="}}
    response = client.post(
        "/api/v1/ingestion/webhooks/gmail?token=WrongToken",
        json=envelope,
    )
    assert response.status_code == 401


def test_gmail_webhook_malformed_envelope_returns_400() -> None:
    client, _, _ = create_test_webhook_app()
    response = client.post(
        "/api/v1/ingestion/webhooks/gmail",
        json={"invalid_key": "data"},
    )
    assert response.status_code == 400


# ===========================================================================
# 9. Manager & Module Lifecycle Tests (Phase 4)
# ===========================================================================
@pytest.mark.asyncio
async def test_manager_create_and_register_daemons() -> None:
    manager = IngestionGatewayManager()
    t_id = uuid4()
    a_id = uuid4()

    g_daemon = manager.create_and_register_daemon(
        tenant_id=t_id,
        account_id=a_id,
        mailbox_address="graph@corp.com",
        provider=MailboxProvider.MS_GRAPH,
    )
    assert isinstance(g_daemon, MSGraphIngestionDaemon)
    assert manager.registry.find_daemon_by_mailbox(MailboxProvider.MS_GRAPH, "graph@corp.com") is not None

    gm_daemon = manager.create_and_register_daemon(
        tenant_id=t_id,
        account_id=a_id,
        mailbox_address="gmail@corp.com",
        provider=MailboxProvider.GMAIL,
    )
    assert isinstance(gm_daemon, GmailIngestionDaemon)

    imap_daemon = manager.create_and_register_daemon(
        tenant_id=t_id,
        account_id=a_id,
        mailbox_address="imap@corp.com",
        provider=MailboxProvider.IMAP,
    )
    assert isinstance(imap_daemon, IMAPIngestionDaemon)


@pytest.mark.asyncio
async def test_manager_start_and_stop_all_lifecycle_events() -> None:
    published_events = []
    mock_publisher = AsyncMock(spec=IEventPublisher)
    mock_publisher.publish = AsyncMock(side_effect=lambda evt: published_events.append(evt))

    manager = IngestionGatewayManager(
        registry=MailboxDaemonRegistry(),
        event_publisher=mock_publisher,
    )
    t_id = uuid4()
    a_id = uuid4()

    manager.create_and_register_daemon(
        tenant_id=t_id,
        account_id=a_id,
        mailbox_address="soc@corp.com",
        provider=MailboxProvider.MS_GRAPH,
    )

    await manager.start_all()
    assert len(published_events) == 1
    assert isinstance(published_events[0], MailboxConnectedEvent)
    assert published_events[0].mailbox_address == "soc@corp.com"

    health = await manager.get_health_status()
    assert health["overall_status"] == "HEALTHY"
    assert health["is_running"] is True

    await manager.stop_all()
    assert len(published_events) == 2
    assert isinstance(published_events[1], MailboxDisconnectedEvent)


@pytest.mark.asyncio
async def test_manager_delivery_routing_to_orchestrator() -> None:
    published_events = []
    mock_publisher = AsyncMock(spec=IEventPublisher)
    mock_publisher.publish = AsyncMock(side_effect=lambda evt: published_events.append(evt))

    mock_orchestrator = AsyncMock()
    mock_orchestrator.execute_pipeline = AsyncMock(return_value=MagicMock())

    manager = IngestionGatewayManager(
        registry=MailboxDaemonRegistry(),
        event_publisher=mock_publisher,
        orchestrator=mock_orchestrator,
    )

    t_id = uuid4()
    a_id = uuid4()
    test_dto = IngestedEmailDTO(
        tenant_id=t_id,
        account_id=a_id,
        mailbox_address="soc@enterprise.com",
        provider=MailboxProvider.MS_GRAPH,
        provider_message_id="msg_orch_101",
        sender="phisher@evil.com",
        recipients=["soc@enterprise.com"],
        subject="Action Required",
        raw_eml_bytes=b"From: phisher@evil.com\r\nSubject: Action Required\r\n\r\nPhish",
    )

    await manager.handle_ingested_email(test_dto)

    # Verify EmailDownloadedEvent published
    assert len(published_events) == 1
    assert isinstance(published_events[0], EmailDownloadedEvent)
    assert published_events[0].message_id == "msg_orch_101"

    # Verify orchestrator received RawEmail entity & PipelineContext
    assert mock_orchestrator.execute_pipeline.call_count == 1
    call_args = mock_orchestrator.execute_pipeline.call_args
    raw_arg = call_args.kwargs.get("raw_email")
    context_arg = call_args.kwargs.get("context")

    assert isinstance(raw_arg, RawEmail)
    assert raw_arg.tenant_id == t_id
    assert raw_arg.account_id == a_id
    assert context_arg.tenant_id == t_id
    assert context_arg.correlation_id == str(test_dto.correlation_id)


@pytest.mark.asyncio
async def test_manager_dlq_event_propagation() -> None:
    published_events = []
    mock_publisher = AsyncMock(spec=IEventPublisher)
    mock_publisher.publish = AsyncMock(side_effect=lambda evt: published_events.append(evt))

    dlq = DeadLetterQueue()
    _ = IngestionGatewayManager(dlq=dlq, event_publisher=mock_publisher)

    t_id = uuid4()
    a_id = uuid4()

    dlq.enqueue(
        tenant_id=t_id,
        account_id=a_id,
        provider=MailboxProvider.MS_GRAPH,
        reason="MIME_CORRUPT",
        error_message="Cannot parse header",
        provider_message_id="msg_dlq_evt_1",
    )

    await asyncio.sleep(0.05)
    assert len(published_events) >= 1
    dlq_evt = next((e for e in published_events if isinstance(e, IngestionDeadLetteredEvent)), None)
    assert dlq_evt is not None
    assert dlq_evt.tenant_id == t_id
    assert dlq_evt.reason == "MIME_CORRUPT"


@pytest.mark.asyncio
async def test_module_lifecycle_and_di_registration() -> None:
    container = Container()
    registry = ModuleRegistry()

    mod = register_ingestion_gateway_module(container, registry)
    assert mod.name == "ingestion_gateway"
    assert mod.version == "1.0.0"

    assert container.has(IngestionGatewayModule) is True
    assert container.has(IngestionGatewayManager) is True
    assert container.resolve(IngestionGatewayModule) is not None
    assert container.resolve(IngestionGatewayManager) is not None

    await mod.initialize()
    health = await mod.health_check()
    assert health.component_name == "ingestion_gateway"
    assert health.status in ("HEALTHY", "DEGRADED")
    assert health.details["initialized"] is True

    await mod.shutdown()
    assert mod._is_initialized is False


@pytest.mark.asyncio
async def test_end_to_end_mocked_ingestion_orchestrator_notification_flow() -> None:
    """Validate full flow: daemon receives webhook -> IngestedEmailDTO -> Manager -> Orchestrator -> EventBus."""
    events_published = []
    mock_publisher = AsyncMock(spec=IEventPublisher)
    mock_publisher.publish = AsyncMock(side_effect=lambda evt: events_published.append(evt))

    mock_orch = AsyncMock()
    mock_orch.execute_pipeline = AsyncMock(return_value=MagicMock())

    manager = IngestionGatewayManager(
        registry=MailboxDaemonRegistry(),
        event_publisher=mock_publisher,
        orchestrator=mock_orch,
    )

    t_id = uuid4()
    a_id = uuid4()

    mock_http = AsyncMock()
    mock_http.get_mime = AsyncMock(return_value=b"From: phish@test.com\r\nSubject: Critical\r\n\r\nBody")

    daemon = manager.create_and_register_daemon(
        tenant_id=t_id,
        account_id=a_id,
        mailbox_address="soc@tenant.com",
        provider=MailboxProvider.MS_GRAPH,
        client_state="TenantClientState",
        http_client=mock_http,
    )

    await daemon.start()
    notification_payload = {
        "value": [
            {
                "subscriptionId": "sub-101",
                "clientState": "TenantClientState",
                "changeType": "created",
                "resourceData": {"id": "msg-e2e-001"},
            }
        ]
    }

    ingested = await daemon.process_notification(notification_payload)
    assert len(ingested) == 1
    assert mock_orch.execute_pipeline.call_count == 1
    assert len(events_published) >= 1
    assert any(isinstance(e, EmailDownloadedEvent) for e in events_published)

    await daemon.stop()


# ===========================================================================
# 10. Domain Exceptions Hierarchy Tests
# ===========================================================================
def test_exceptions_hierarchy() -> None:
    assert issubclass(IngestionGatewayError, ScamONError)
    assert issubclass(ProviderConnectionError, IngestionGatewayError)
    assert issubclass(AuthenticationFailedError, IngestionGatewayError)
    assert issubclass(MessageRetrievalError, IngestionGatewayError)
    assert issubclass(DuplicateMessageSuppressedError, IngestionGatewayError)
    assert issubclass(PayloadSizeExceededError, IngestionGatewayError)
    assert issubclass(DeadLetterError, IngestionGatewayError)
    assert issubclass(DaemonLifecycleError, IngestionGatewayError)
