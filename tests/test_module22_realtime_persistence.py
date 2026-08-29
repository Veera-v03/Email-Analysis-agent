"""Targeted unit and integration tests for Module 22 (Phases 1, 2 & 3: DLQ Persistence, Account Sync, Real-Time SOC Stream)."""

from __future__ import annotations

import asyncio
import json
from pathlib import Path
from typing import Any
from unittest.mock import AsyncMock, patch
from uuid import UUID, uuid4

import pytest
from fastapi import WebSocketDisconnect

from src.events.security_events import RiskScoredEvent
from src.ingestion_gateway.coordinator import AccountSyncCoordinator
from src.ingestion_gateway.dead_letter import (
    DeadLetterItemDTO,
    DeadLetterQueue,
)
from src.ingestion_gateway.dedup import IngestionDeduplicationEngine
from src.ingestion_gateway.manager import IngestionGatewayManager
from src.ingestion_gateway.models import MailboxProvider
from src.ingestion_gateway.persistence.file_storage import FileBackedDeadLetterStorage
from src.ingestion_gateway.persistence.in_memory import InMemoryDeadLetterStorage
from src.ingestion_gateway.webhook_handler import MailboxDaemonRegistry
from src.realtime.broadcaster import (
    SOCEventBroadcaster,
    WebSocketClient,
)
from src.realtime.router import soc_event_websocket_endpoint
from src.security.auth import create_jwt_token


# ===========================================================================
# 1. InMemoryDeadLetterStorage Unit Tests
# ===========================================================================
def test_in_memory_storage_save_get_and_count() -> None:
    storage = InMemoryDeadLetterStorage(max_items=10)
    t_id = uuid4()
    a_id = uuid4()

    item = DeadLetterItemDTO(
        tenant_id=t_id,
        account_id=a_id,
        provider=MailboxProvider.MS_GRAPH,
        reason="PAYLOAD_CORRUPT",
        error_message="Header parsing failed",
    )

    storage.save(item)
    assert storage.count() == 1
    assert storage.count(t_id) == 1

    fetched = storage.get(item.dead_letter_id)
    assert fetched is not None
    assert fetched.dead_letter_id == item.dead_letter_id
    assert fetched.reason == "PAYLOAD_CORRUPT"


def test_in_memory_storage_tenant_isolation_and_clear() -> None:
    storage = InMemoryDeadLetterStorage(max_items=10)
    t1 = uuid4()
    t2 = uuid4()
    a_id = uuid4()

    i1 = DeadLetterItemDTO(tenant_id=t1, account_id=a_id, provider=MailboxProvider.GMAIL, reason="R1", error_message="e1")
    i2 = DeadLetterItemDTO(tenant_id=t2, account_id=a_id, provider=MailboxProvider.IMAP, reason="R2", error_message="e2")

    storage.save(i1)
    storage.save(i2)

    assert storage.count(t1) == 1
    assert storage.count(t2) == 1
    assert len(storage.list_items(tenant_id=t1)) == 1
    assert len(storage.list_items(tenant_id=t2)) == 1

    cleared = storage.clear_tenant(t1)
    assert cleared == 1
    assert storage.count(t1) == 0
    assert storage.count(t2) == 1


def test_in_memory_storage_capacity_bounding() -> None:
    storage = InMemoryDeadLetterStorage(max_items=2)
    t = uuid4()
    a = uuid4()

    i1 = DeadLetterItemDTO(tenant_id=t, account_id=a, provider=MailboxProvider.MS_GRAPH, reason="R1", error_message="e1")
    i2 = DeadLetterItemDTO(tenant_id=t, account_id=a, provider=MailboxProvider.MS_GRAPH, reason="R2", error_message="e2")
    i3 = DeadLetterItemDTO(tenant_id=t, account_id=a, provider=MailboxProvider.MS_GRAPH, reason="R3", error_message="e3")

    storage.save(i1)
    storage.save(i2)
    storage.save(i3)

    assert storage.count() == 2
    assert storage.get(i1.dead_letter_id) is None
    assert storage.get(i2.dead_letter_id) is not None
    assert storage.get(i3.dead_letter_id) is not None


# ===========================================================================
# 2. FileBackedDeadLetterStorage Unit & Persistence Tests
# ===========================================================================
def test_file_storage_save_get_and_persistence_across_instances(tmp_path: Path) -> None:
    storage_dir = tmp_path / "dlq_store"
    storage1 = FileBackedDeadLetterStorage(storage_dir=storage_dir, max_items=10)

    t_id = uuid4()
    a_id = uuid4()
    item = DeadLetterItemDTO(
        tenant_id=t_id,
        account_id=a_id,
        provider=MailboxProvider.MS_GRAPH,
        reason="MIME_OVERSIZED",
        error_message="Exceeded 50MB",
        provider_message_id="graph_msg_999",
        raw_payload="A" * 500,
    )

    storage1.save(item)
    assert storage1.count() == 1
    assert storage1.count(t_id) == 1

    # Simulate process restart by creating a new storage instance pointing to same dir
    storage2 = FileBackedDeadLetterStorage(storage_dir=storage_dir, max_items=10)
    assert storage2.count() == 1

    recovered = storage2.get(item.dead_letter_id)
    assert recovered is not None
    assert recovered.dead_letter_id == item.dead_letter_id
    assert recovered.tenant_id == t_id
    assert recovered.provider == MailboxProvider.MS_GRAPH
    assert recovered.reason == "MIME_OVERSIZED"
    assert recovered.raw_payload == "A" * 500


def test_file_storage_tenant_isolation_and_clear_tenant(tmp_path: Path) -> None:
    storage_dir = tmp_path / "dlq_tenant_test"
    storage = FileBackedDeadLetterStorage(storage_dir=storage_dir, max_items=10)

    t1 = uuid4()
    t2 = uuid4()
    a = uuid4()

    i1 = DeadLetterItemDTO(tenant_id=t1, account_id=a, provider=MailboxProvider.GMAIL, reason="T1_ERR", error_message="err1")
    i2 = DeadLetterItemDTO(tenant_id=t2, account_id=a, provider=MailboxProvider.IMAP, reason="T2_ERR", error_message="err2")

    storage.save(i1)
    storage.save(i2)

    t1_list = storage.list_items(tenant_id=t1)
    assert len(t1_list) == 1
    assert t1_list[0].dead_letter_id == i1.dead_letter_id

    t2_list = storage.list_items(tenant_id=t2)
    assert len(t2_list) == 1
    assert t2_list[0].dead_letter_id == i2.dead_letter_id

    cleared = storage.clear_tenant(t1)
    assert cleared == 1
    assert storage.count(t1) == 0
    assert storage.count(t2) == 1
    assert storage.get(i1.dead_letter_id) is None
    assert storage.get(i2.dead_letter_id) is not None


def test_file_storage_capacity_bounding_and_eviction(tmp_path: Path) -> None:
    storage_dir = tmp_path / "dlq_capacity_test"
    storage = FileBackedDeadLetterStorage(storage_dir=storage_dir, max_items=2)

    t = uuid4()
    a = uuid4()

    i1 = DeadLetterItemDTO(tenant_id=t, account_id=a, provider=MailboxProvider.IMAP, reason="E1", error_message="msg1")
    i2 = DeadLetterItemDTO(tenant_id=t, account_id=a, provider=MailboxProvider.IMAP, reason="E2", error_message="msg2")
    i3 = DeadLetterItemDTO(tenant_id=t, account_id=a, provider=MailboxProvider.IMAP, reason="E3", error_message="msg3")

    storage.save(i1)
    storage.save(i2)
    storage.save(i3)

    assert storage.count() == 2
    # Total json files in directory must not exceed max_items
    json_files = list(storage_dir.glob("dlq_*.json"))
    assert len(json_files) == 2


def test_file_storage_delete(tmp_path: Path) -> None:
    storage_dir = tmp_path / "dlq_delete_test"
    storage = FileBackedDeadLetterStorage(storage_dir=storage_dir, max_items=10)

    item = DeadLetterItemDTO(
        tenant_id=uuid4(),
        account_id=uuid4(),
        provider=MailboxProvider.MS_GRAPH,
        reason="TO_DELETE",
        error_message="test",
    )

    storage.save(item)
    assert storage.get(item.dead_letter_id) is not None

    deleted = storage.delete(item.dead_letter_id)
    assert deleted is True
    assert storage.get(item.dead_letter_id) is None
    assert storage.delete(item.dead_letter_id) is False


# ===========================================================================
# 3. DeadLetterQueue Integration with File Storage Tests
# ===========================================================================
def test_dead_letter_queue_with_file_storage_workflow(tmp_path: Path) -> None:
    storage_dir = tmp_path / "dlq_queue_integration"
    storage = FileBackedDeadLetterStorage(storage_dir=storage_dir, max_items=10)
    dlq = DeadLetterQueue(storage=storage)

    t_id = uuid4()
    a_id = uuid4()

    enqueued = dlq.enqueue(
        tenant_id=t_id,
        account_id=a_id,
        provider=MailboxProvider.MS_GRAPH,
        reason="PIPELINE_ERROR",
        error_message="Orchestrator timeout",
        provider_message_id="msg_queue_001",
        raw_payload="X" * 10000,  # Must be bounded to 8KB
    )

    assert isinstance(enqueued, DeadLetterItemDTO)
    assert len(enqueued.raw_payload) == 8192  # 8KB bounded

    fetched = dlq.get(enqueued.dead_letter_id)
    assert fetched is not None
    assert fetched.dead_letter_id == enqueued.dead_letter_id

    # Requeue test
    r1 = dlq.requeue(enqueued.dead_letter_id)
    assert r1 is not None
    assert r1.retry_count == 1

    r2 = dlq.requeue(enqueued.dead_letter_id)
    assert r2.retry_count == 2

    r3 = dlq.requeue(enqueued.dead_letter_id)
    assert r3.retry_count == 3

    r4 = dlq.requeue(enqueued.dead_letter_id)
    assert r4 is None  # max_retries (3) reached

    # Stats test
    stats = dlq.get_stats()
    assert stats["current_size"] == 1
    assert stats["total_enqueued"] == 1
    assert stats["total_requeued"] == 3

    # Purge test
    assert dlq.purge(enqueued.dead_letter_id) is True
    assert dlq.get(enqueued.dead_letter_id) is None


def test_dead_letter_queue_event_hook_with_file_storage(tmp_path: Path) -> None:
    storage_dir = tmp_path / "dlq_hook_test"
    storage = FileBackedDeadLetterStorage(storage_dir=storage_dir, max_items=10)
    dlq = DeadLetterQueue(storage=storage)

    hook_called = False
    hook_item: DeadLetterItemDTO | None = None

    def _on_dlq(item: DeadLetterItemDTO) -> None:
        nonlocal hook_called, hook_item
        hook_called = True
        hook_item = item

    dlq.set_event_hook(_on_dlq)

    item = dlq.enqueue(
        tenant_id=uuid4(),
        account_id=uuid4(),
        provider=MailboxProvider.GMAIL,
        reason="PUB_SUB_ERROR",
        error_message="Invalid signature",
    )

    assert hook_called is True
    assert hook_item is not None
    assert hook_item.dead_letter_id == item.dead_letter_id


def test_dead_letter_queue_backward_compatibility_default_in_memory() -> None:
    """Verify that DeadLetterQueue() without explicit storage defaults to in-memory storage seamlessly."""
    dlq = DeadLetterQueue(max_items=5)
    assert isinstance(dlq.storage, InMemoryDeadLetterStorage)

    t_id = uuid4()
    a_id = uuid4()
    item = dlq.enqueue(
        tenant_id=t_id,
        account_id=a_id,
        provider=MailboxProvider.IMAP,
        reason="IN_MEM_TEST",
        error_message="socket error",
    )

    assert dlq.get(item.dead_letter_id) is not None
    assert len(dlq.list_items()) == 1
    assert dlq.purge(item.dead_letter_id) is True
    assert dlq.get(item.dead_letter_id) is None


# ===========================================================================
# 4. AccountSyncCoordinator Unit & Integration Tests (Phase 2)
# ===========================================================================
class MockAccountRecord:
    """Mock database entity representing EmailAccount."""

    def __init__(
        self,
        tenant_id: UUID,
        account_id: UUID,
        email_address: str,
        provider: str = "GMAIL",
        access_token: str | None = "token_abc",
        refresh_token: str | None = "ref_xyz",
        is_active: bool = True,
    ) -> None:
        self.tenant_id = tenant_id
        self.id = account_id
        self.email_address = email_address
        self.provider = provider
        self.access_token = access_token
        self.refresh_token = refresh_token
        self.is_active = is_active


@pytest.mark.asyncio
async def test_coordinator_discovery_and_daemon_creation() -> None:
    registry = MailboxDaemonRegistry()
    dedup = IngestionDeduplicationEngine()
    dlq = DeadLetterQueue()
    manager = IngestionGatewayManager(registry=registry, dedup_engine=dedup, dlq=dlq)

    t_id = uuid4()
    acc_gmail = MockAccountRecord(t_id, uuid4(), "user@gmail.com", provider="GMAIL")
    acc_graph = MockAccountRecord(t_id, uuid4(), "user@corp.com", provider="MS_GRAPH")
    acc_imap = MockAccountRecord(t_id, uuid4(), "user@imap.com", provider="IMAP")

    accounts = [acc_gmail, acc_graph, acc_imap]

    async def mock_repo() -> list[MockAccountRecord]:
        return accounts

    coordinator = AccountSyncCoordinator(manager=manager, account_repo=mock_repo, sync_interval_sec=1.0)

    # Patch start() on provider daemons to avoid real network socket/HTTP calls
    with patch("src.ingestion_gateway.providers.gmail_daemon.GmailIngestionDaemon.start", new_callable=AsyncMock), \
         patch("src.ingestion_gateway.providers.msgraph_daemon.MSGraphIngestionDaemon.start", new_callable=AsyncMock), \
         patch("src.ingestion_gateway.providers.imap_daemon.IMAPIngestionDaemon.start", new_callable=AsyncMock):

        summary = await coordinator.reconcile_once()

    assert summary["sync_cycles"] == 1
    assert summary["active_accounts"] == 3
    assert summary["active_daemons"] == 3
    assert summary["total_spawned"] == 3

    # Verify daemons registered
    assert registry.get_daemon(t_id, acc_gmail.id, MailboxProvider.GMAIL) is not None
    assert registry.get_daemon(t_id, acc_graph.id, MailboxProvider.MS_GRAPH) is not None
    assert registry.get_daemon(t_id, acc_imap.id, MailboxProvider.IMAP) is not None


@pytest.mark.asyncio
async def test_coordinator_duplicate_prevention_on_second_sweep() -> None:
    registry = MailboxDaemonRegistry()
    manager = IngestionGatewayManager(registry=registry)
    t_id = uuid4()
    acc = MockAccountRecord(t_id, uuid4(), "admin@corp.com", provider="MS_GRAPH")

    coordinator = AccountSyncCoordinator(manager=manager, account_repo=lambda: [acc])

    with patch("src.ingestion_gateway.providers.msgraph_daemon.MSGraphIngestionDaemon.start", new_callable=AsyncMock):
        s1 = await coordinator.reconcile_once()
        assert s1["total_spawned"] == 1

        # Second sweep
        s2 = await coordinator.reconcile_once()
        assert s2["total_spawned"] == 1  # No duplicate spawn
        assert s2["active_daemons"] == 1


@pytest.mark.asyncio
async def test_coordinator_deactivated_and_deleted_account_termination() -> None:
    registry = MailboxDaemonRegistry()
    manager = IngestionGatewayManager(registry=registry)
    t_id = uuid4()
    a1 = MockAccountRecord(t_id, uuid4(), "active@corp.com", provider="MS_GRAPH", is_active=True)
    a2 = MockAccountRecord(t_id, uuid4(), "to_deactivate@corp.com", provider="GMAIL", is_active=True)

    accounts = [a1, a2]
    coordinator = AccountSyncCoordinator(manager=manager, account_repo=lambda: accounts)

    with patch("src.ingestion_gateway.providers.msgraph_daemon.MSGraphIngestionDaemon.start", new_callable=AsyncMock), \
         patch("src.ingestion_gateway.providers.gmail_daemon.GmailIngestionDaemon.start", new_callable=AsyncMock), \
         patch("src.ingestion_gateway.providers.gmail_daemon.GmailIngestionDaemon.stop", new_callable=AsyncMock) as mock_stop:

        await coordinator.reconcile_once()
        assert len(registry.list_daemons()) == 2

        # Deactivate a2
        a2.is_active = False
        summary = await coordinator.reconcile_once()

        assert summary["active_daemons"] == 1
        assert summary["total_terminated"] == 1
        assert registry.get_daemon(t_id, a2.id, MailboxProvider.GMAIL) is None
        assert registry.get_daemon(t_id, a1.id, MailboxProvider.MS_GRAPH) is not None
        mock_stop.assert_awaited()


@pytest.mark.asyncio
async def test_coordinator_credential_update_triggers_restart() -> None:
    registry = MailboxDaemonRegistry()
    manager = IngestionGatewayManager(registry=registry)
    t_id = uuid4()
    a_id = uuid4()
    acc = MockAccountRecord(t_id, a_id, "user@corp.com", provider="GMAIL", access_token="initial_token")

    coordinator = AccountSyncCoordinator(manager=manager, account_repo=lambda: [acc])

    with patch("src.ingestion_gateway.providers.gmail_daemon.GmailIngestionDaemon.start", new_callable=AsyncMock), \
         patch("src.ingestion_gateway.providers.gmail_daemon.GmailIngestionDaemon.stop", new_callable=AsyncMock) as mock_stop:

        await coordinator.reconcile_once()
        old_hash = coordinator._account_config_hashes.get((t_id, a_id))

        # Update token
        acc.access_token = "new_rotated_oauth_token"
        await coordinator.reconcile_once()

        new_hash = coordinator._account_config_hashes.get((t_id, a_id))
        assert old_hash != new_hash
        mock_stop.assert_awaited()
        assert registry.get_daemon(t_id, a_id, MailboxProvider.GMAIL) is not None


@pytest.mark.asyncio
async def test_coordinator_tenant_and_account_isolation() -> None:
    registry = MailboxDaemonRegistry()
    manager = IngestionGatewayManager(registry=registry)
    t1 = uuid4()
    t2 = uuid4()
    a1 = MockAccountRecord(t1, uuid4(), "user@t1.com", provider="IMAP")
    a2 = MockAccountRecord(t2, uuid4(), "user@t2.com", provider="IMAP")

    coordinator = AccountSyncCoordinator(manager=manager, account_repo=lambda: [a1, a2])

    with patch("src.ingestion_gateway.providers.imap_daemon.IMAPIngestionDaemon.start", new_callable=AsyncMock):
        await coordinator.reconcile_once()

    t1_daemons = registry.list_daemons(tenant_id=t1)
    t2_daemons = registry.list_daemons(tenant_id=t2)
    assert len(t1_daemons) == 1
    assert len(t2_daemons) == 1
    assert t1_daemons[0].account_id == a1.id
    assert t2_daemons[0].account_id == a2.id


@pytest.mark.asyncio
async def test_coordinator_failure_isolation_and_exponential_backoff() -> None:
    registry = MailboxDaemonRegistry()
    manager = IngestionGatewayManager(registry=registry)
    t_id = uuid4()
    failing_acc = MockAccountRecord(t_id, uuid4(), "failing@corp.com", provider="MS_GRAPH")
    healthy_acc = MockAccountRecord(t_id, uuid4(), "healthy@corp.com", provider="GMAIL")

    coordinator = AccountSyncCoordinator(manager=manager, account_repo=lambda: [failing_acc, healthy_acc])

    # Failing daemon raises exception on start
    async def mock_fail_start() -> None:
        raise ConnectionResetError("M365 endpoint unreachable")

    with patch("src.ingestion_gateway.providers.msgraph_daemon.MSGraphIngestionDaemon.start", side_effect=mock_fail_start), \
         patch("src.ingestion_gateway.providers.gmail_daemon.GmailIngestionDaemon.start", new_callable=AsyncMock):

        summary = await coordinator.reconcile_once()

    # Healthy daemon was created and registered; failing daemon failed safely
    assert summary["active_daemons"] == 1
    assert summary["backoff_accounts"] == 1
    assert registry.get_daemon(t_id, healthy_acc.id, MailboxProvider.GMAIL) is not None
    assert (t_id, failing_acc.id) in coordinator._consecutive_failures
    assert coordinator._consecutive_failures[(t_id, failing_acc.id)] == 1


@pytest.mark.asyncio
async def test_coordinator_lifecycle_start_stop_and_health() -> None:
    registry = MailboxDaemonRegistry()
    manager = IngestionGatewayManager(registry=registry)
    coordinator = AccountSyncCoordinator(manager=manager, account_repo=lambda: [], sync_interval_sec=0.05)

    assert not coordinator.is_running
    coordinator.start()
    assert coordinator.is_running

    await asyncio.sleep(0.12)
    health = coordinator.health_check()
    assert health["status"] == "HEALTHY"
    assert health["total_sync_cycles"] >= 1

    state = coordinator.get_state()
    assert state["is_running"] is True

    await coordinator.stop()
    assert not coordinator.is_running
    assert coordinator.health_check()["status"] == "STOPPED"


# ===========================================================================
# 5. Real-Time SOC Event Stream Unit & Integration Tests (Phase 3)
# ===========================================================================
class MockWebSocket:
    """Mock FastAPI WebSocket connection for unit testing."""

    def __init__(self) -> None:
        self.sent_messages: list[str] = []
        self.closed = False
        self.close_code: int | None = None
        self.close_reason: str | None = None
        self._receive_queue: asyncio.Queue[str] = asyncio.Queue()

    async def accept(self) -> None:
        pass

    async def send_text(self, text: str) -> None:
        self.sent_messages.append(text)

    async def receive_text(self) -> str:
        msg = await self._receive_queue.get()
        if msg == "__DISCONNECT__":
            raise WebSocketDisconnect(code=1000)
        return msg

    async def close(self, code: int = 1000, reason: str = "Normal Closure") -> None:
        self.closed = True
        self.close_code = code
        self.close_reason = reason


@pytest.mark.asyncio
async def test_broadcaster_client_registration_and_stats() -> None:
    broadcaster = SOCEventBroadcaster(max_clients_per_tenant=5)
    t_id = uuid4()
    ws = MockWebSocket()
    client = WebSocketClient(websocket=ws, tenant_id=t_id)

    registered = await broadcaster.register(client)
    assert registered is True

    stats = broadcaster.get_stats()
    assert stats["total_active_tenants"] == 1
    assert stats["total_active_clients"] == 1

    states = broadcaster.list_client_states(tenant_id=t_id)
    assert len(states) == 1
    assert states[0]["tenant_id"] == t_id

    await broadcaster.unregister(client)
    assert broadcaster.get_stats()["total_active_clients"] == 0


@pytest.mark.asyncio
async def test_broadcaster_tenant_isolation_routing() -> None:
    broadcaster = SOCEventBroadcaster()
    t1 = uuid4()
    t2 = uuid4()

    ws1 = MockWebSocket()
    ws2 = MockWebSocket()

    c1 = WebSocketClient(websocket=ws1, tenant_id=t1)
    c2 = WebSocketClient(websocket=ws2, tenant_id=t2)

    await broadcaster.register(c1)
    await broadcaster.register(c2)

    # Event for Tenant 1 ONLY
    from src.common.constants import ActionTaken, Verdict

    event_t1 = RiskScoredEvent(
        tenant_id=t1,
        incident_id=uuid4(),
        message_id="msg_test_001",
        risk_score=85,
        verdict=Verdict.MALICIOUS,
        threat_categories=["PHISHING"],
        recommended_action=ActionTaken.QUARANTINED,
        explainability_summary="High confidence phishing detection",
    )

    queued = await broadcaster.broadcast_event(event_t1)
    assert queued == 1

    await asyncio.sleep(0.05)  # Allow sender loop to transmit

    assert len(ws1.sent_messages) == 1
    assert len(ws2.sent_messages) == 0  # Tenant 2 received NOTHING

    parsed_msg = json.loads(ws1.sent_messages[0])
    assert parsed_msg["event_type"] == "RiskScoredEvent"
    assert parsed_msg["payload"]["risk_score"] == 85
    assert parsed_msg["payload"]["verdict"] == "MALICIOUS"

    await broadcaster.unregister(c1)
    await broadcaster.unregister(c2)


@pytest.mark.asyncio
async def test_broadcaster_event_sanitization_redacts_secrets() -> None:
    broadcaster = SOCEventBroadcaster()
    t_id = uuid4()
    ws = MockWebSocket()
    client = WebSocketClient(websocket=ws, tenant_id=t_id)
    await broadcaster.register(client)

    # Payload with sensitive secrets
    event_with_secret = {
        "event_type": "RiskScoredEvent",
        "tenant_id": str(t_id),
        "api_key": "secret_key_123456",
        "password": "SuperSecretPassword123!",
        "raw_body": "Hello world with sensitive payload",
        "details": "User auth header: Bearer abcdef1234567890",
        "risk_level": "CRITICAL",
    }

    await broadcaster.broadcast_event(event_with_secret)
    await asyncio.sleep(0.05)

    assert len(ws.sent_messages) == 1
    delivered = json.loads(ws.sent_messages[0])
    payload = delivered["payload"]

    assert payload["api_key"] == "[REDACTED]"
    assert payload["password"] == "[REDACTED]"
    assert payload["raw_body"] == "[REDACTED]"
    assert "Bearer [REDACTED]" in payload["details"]
    assert payload["risk_level"] == "CRITICAL"

    await broadcaster.unregister(client)


@pytest.mark.asyncio
async def test_broadcaster_backpressure_and_slow_client_drop() -> None:
    # Client with max_queue_size = 2
    ws = MockWebSocket()
    t_id = uuid4()
    client = WebSocketClient(websocket=ws, tenant_id=t_id, max_queue_size=2)
    # Do not start sender loop to simulate hung/slow client

    client.enqueue_event("event_1")
    client.enqueue_event("event_2")
    assert client.queue.qsize() == 2

    # Third event drops oldest ("event_1") and enqueues "event_3"
    success = client.enqueue_event("event_3")
    assert success is True
    assert client.state.dropped_events == 1
    assert client.queue.qsize() == 2

    item_a = client.queue.get_nowait()
    item_b = client.queue.get_nowait()
    assert item_a == "event_2"
    assert item_b == "event_3"


@pytest.mark.asyncio
async def test_broadcaster_max_clients_per_tenant_limit() -> None:
    broadcaster = SOCEventBroadcaster(max_clients_per_tenant=2)
    t_id = uuid4()

    c1 = WebSocketClient(websocket=MockWebSocket(), tenant_id=t_id)
    c2 = WebSocketClient(websocket=MockWebSocket(), tenant_id=t_id)
    c3 = WebSocketClient(websocket=MockWebSocket(), tenant_id=t_id)

    assert await broadcaster.register(c1) is True
    assert await broadcaster.register(c2) is True
    # Exceeds max_clients_per_tenant (2)
    assert await broadcaster.register(c3) is False

    await broadcaster.unregister(c1)
    await broadcaster.unregister(c2)


@pytest.mark.asyncio
async def test_broadcaster_heartbeat_and_pruning() -> None:
    broadcaster = SOCEventBroadcaster(
        heartbeat_interval_sec=0.05,
        client_timeout_sec=0.1,
    )
    t_id = uuid4()
    ws = MockWebSocket()
    client = WebSocketClient(websocket=ws, tenant_id=t_id)
    await broadcaster.register(client)

    broadcaster.start()
    assert broadcaster.is_running

    # Active client receives heartbeat
    await asyncio.sleep(0.08)
    assert len(ws.sent_messages) >= 1
    hb = json.loads(ws.sent_messages[0])
    assert hb["event_type"] == "HEARTBEAT_PING"

    await broadcaster.stop()
    assert not broadcaster.is_running


@pytest.mark.asyncio
async def test_realtime_router_authentication_and_tenant_validation() -> None:
    broadcaster = SOCEventBroadcaster()
    t1 = uuid4()
    t2 = uuid4()

    # Valid token for tenant 1
    valid_token_t1 = create_jwt_token({
        "sub": str(uuid4()),
        "tenant_id": str(t1),
        "roles": ["SOC_ANALYST"],
    })

    # 1. Unauthenticated test (no token)
    ws_unauth = MockWebSocket()
    await soc_event_websocket_endpoint(
        websocket=ws_unauth,
        token=None,
        tenant_id=None,
        broadcaster=broadcaster,
    )
    assert ws_unauth.closed is True
    assert ws_unauth.close_code == 1008

    # 2. Cross-tenant hijacking test (Token for T1, Query for T2)
    ws_cross = MockWebSocket()
    await soc_event_websocket_endpoint(
        websocket=ws_cross,
        token=valid_token_t1,
        tenant_id=str(t2),
        broadcaster=broadcaster,
    )
    assert ws_cross.closed is True
    assert ws_cross.close_code == 1008
    assert ws_cross.close_reason == "Cross-tenant access forbidden"


# ===========================================================================
# 6. RealtimeModule DI Container & Lifecycle Integration Tests (Phase 4)
# ===========================================================================
@pytest.mark.asyncio
async def test_realtime_module_lifecycle_and_di_registration() -> None:
    from src.container.di import Container
    from src.realtime.module import RealtimeModule, register_realtime_module
    from src.registry.module_registry import ModuleRegistry

    container = Container()
    registry = ModuleRegistry()

    module = register_realtime_module(container, registry)
    assert isinstance(module, RealtimeModule)
    assert container.has(SOCEventBroadcaster)
    assert container.has(RealtimeModule)
    assert registry.get_module("realtime") is not None

    assert not module._is_initialized
    await module.initialize()
    assert module._is_initialized
    assert module.broadcaster.is_running

    health = await module.health_check()
    assert health.component_name == "realtime"
    assert health.status == "HEALTHY"
    assert health.details["initialized"] is True

    await module.shutdown()
    assert not module._is_initialized
    assert not module.broadcaster.is_running


@pytest.mark.asyncio
async def test_realtime_module_eventbus_auto_subscription() -> None:
    from src.container.di import Container
    from src.events.base_event import BaseEvent
    from src.interfaces.event_publisher import IEventPublisher
    from src.realtime.module import register_realtime_module
    from src.registry.module_registry import ModuleRegistry

    container = Container()
    registry = ModuleRegistry()

    subscribed_events: list[type] = []

    class MockEventBus:
        async def publish(self, event: BaseEvent) -> None:
            pass

        def subscribe(self, event_cls: type, handler: Any) -> None:
            subscribed_events.append(event_cls)

    container.register_instance(IEventPublisher, MockEventBus())

    module = register_realtime_module(container, registry)
    await module.initialize()

    assert len(subscribed_events) > 0
    assert RiskScoredEvent in subscribed_events
    await module.shutdown()
