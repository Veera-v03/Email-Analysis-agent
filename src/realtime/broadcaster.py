"""Real-Time SOC Event Broadcaster with Tenant Isolation and Backpressure (Module 22)."""

from __future__ import annotations

import asyncio
import json
from datetime import UTC, datetime
from typing import Any
from uuid import UUID, uuid4

from pydantic import BaseModel, ConfigDict, Field

from src.config.enterprise_config import settings
from src.events.base_event import BaseEvent
from src.notifications.sanitizer import sanitize_metadata
from src.utils.logging import get_logger

logger = get_logger(__name__)


class ClientConnectionState(BaseModel):
    """Diagnostic and telemetry state tracking an individual SOC WebSocket client connection."""

    model_config = ConfigDict(arbitrary_types_allowed=True)

    connection_id: UUID = Field(default_factory=uuid4, description="Unique connection UUID")
    tenant_id: UUID = Field(description="Authenticated enterprise tenant UUID")
    user_id: UUID | None = Field(default=None, description="Authenticated principal UUID")
    connected_at: datetime = Field(
        default_factory=lambda: datetime.now(UTC), description="Connection start timestamp"
    )
    last_activity: datetime = Field(
        default_factory=lambda: datetime.now(UTC), description="Last active frame timestamp"
    )
    queued_events: int = Field(default=0, ge=0, description="Currently queued events")
    dropped_events: int = Field(default=0, ge=0, description="Total dropped events due to overflow")
    total_sent: int = Field(default=0, ge=0, description="Total successfully transmitted events")
    status: str = Field(default="CONNECTED", description="Connection status string")


class WebSocketClient:
    """Represents an active, authenticated WebSocket client session with bounded async queue."""

    def __init__(
        self,
        websocket: Any,
        tenant_id: UUID,
        user_id: UUID | None = None,
        max_queue_size: int = 100,
    ) -> None:
        self.websocket = websocket
        self.state = ClientConnectionState(
            tenant_id=tenant_id,
            user_id=user_id,
        )
        self.queue: asyncio.Queue[str] = asyncio.Queue(maxsize=max_queue_size)
        self.max_queue_size = max_queue_size
        self._sender_task: asyncio.Task[None] | None = None
        self._is_active = True

    def start_sender(self) -> None:
        """Start the background consumer task that sends queued events down the WebSocket."""
        if self._sender_task is None or self._sender_task.done():
            self._sender_task = asyncio.create_task(self._sender_loop())

    async def _sender_loop(self) -> None:
        """Continuously pulls sanitized events from bounded queue and transmits them to client."""
        while self._is_active:
            try:
                message = await self.queue.get()
                self.state.queued_events = self.queue.qsize()

                # Send text down WebSocket
                if hasattr(self.websocket, "send_text"):
                    res = self.websocket.send_text(message)
                    if asyncio.iscoroutine(res):
                        await res
                elif hasattr(self.websocket, "send"):
                    res = self.websocket.send(message)
                    if asyncio.iscoroutine(res):
                        await res

                self.state.total_sent += 1
                self.state.last_activity = datetime.now(UTC)
                self.queue.task_done()
            except asyncio.CancelledError:
                break
            except Exception as send_exc:
                logger.warning(
                    "Error transmitting WebSocket event to client %s: %s",
                    self.state.connection_id,
                    send_exc,
                )
                self._is_active = False
                break

    def enqueue_event(self, event_json: str) -> bool:
        """Enqueue event with FIFO drop-oldest backpressure if client is slower than producer."""
        if not self._is_active:
            return False

        if self.queue.full():
            # Drop oldest event to maintain bounded memory and unblock stream
            try:
                self.queue.get_nowait()
                self.queue.task_done()
                self.state.dropped_events += 1
            except (asyncio.QueueEmpty, ValueError):
                pass

        try:
            self.queue.put_nowait(event_json)
            self.state.queued_events = self.queue.qsize()
            return True
        except asyncio.QueueFull:
            self.state.dropped_events += 1
            return False

    async def close(self, code: int = 1000, reason: str = "Normal Closure") -> None:
        """Gracefully close client connection and stop sender task."""
        self._is_active = False
        if self._sender_task:
            self._sender_task.cancel()
            try:
                await self._sender_task
            except asyncio.CancelledError:
                pass
            self._sender_task = None

        try:
            if hasattr(self.websocket, "close"):
                res = self.websocket.close(code=code, reason=reason)
                if asyncio.iscoroutine(res):
                    await res
        except Exception:
            pass

        self.state.status = "DISCONNECTED"


class SOCEventBroadcaster:
    """Thread-safe, multi-tenant WebSocket security event broadcaster with sanitization and backpressure."""

    def __init__(
        self,
        max_client_queue: int | None = None,
        max_clients_per_tenant: int | None = None,
        heartbeat_interval_sec: float | None = None,
        client_timeout_sec: float | None = None,
    ) -> None:
        self.max_client_queue = (
            max_client_queue
            if max_client_queue is not None
            else settings.realtime_max_client_queue
        )
        self.max_clients_per_tenant = (
            max_clients_per_tenant
            if max_clients_per_tenant is not None
            else settings.realtime_max_clients_per_tenant
        )
        self.heartbeat_interval_sec = (
            heartbeat_interval_sec
            if heartbeat_interval_sec is not None
            else settings.realtime_heartbeat_interval_sec
        )
        self.client_timeout_sec = (
            client_timeout_sec
            if client_timeout_sec is not None
            else settings.realtime_client_timeout_sec
        )

        self._lock = asyncio.Lock()
        # Tenant UUID -> list of active WebSocketClient sessions
        self._clients: dict[UUID, list[WebSocketClient]] = {}
        self._is_running = False
        self._heartbeat_task: asyncio.Task[None] | None = None
        self._total_broadcasts: int = 0
        self._total_events_published: int = 0

    @property
    def is_running(self) -> bool:
        """Return True if broadcaster background heartbeat loop is active."""
        return self._is_running

    async def register(self, client: WebSocketClient) -> bool:
        """Register a new authenticated WebSocket client under its tenant boundary."""
        async with self._lock:
            tenant_id = client.state.tenant_id
            tenant_clients = self._clients.setdefault(tenant_id, [])

            if len(tenant_clients) >= self.max_clients_per_tenant:
                logger.warning(
                    "Rejecting WebSocket client for tenant %s: exceeded max clients limit (%d)",
                    tenant_id,
                    self.max_clients_per_tenant,
                )
                return False

            tenant_clients.append(client)
            client.start_sender()
            logger.info(
                "Registered SOC WebSocket client (id=%s, tenant=%s, active_for_tenant=%d)",
                client.state.connection_id,
                tenant_id,
                len(tenant_clients),
            )
            return True

    async def unregister(self, client: WebSocketClient) -> None:
        """Unregister and close a WebSocket client session."""
        async with self._lock:
            tenant_id = client.state.tenant_id
            if tenant_id in self._clients:
                try:
                    self._clients[tenant_id].remove(client)
                except ValueError:
                    pass

                if not self._clients[tenant_id]:
                    del self._clients[tenant_id]

        await client.close()
        logger.info(
            "Unregistered SOC WebSocket client %s (tenant=%s)",
            client.state.connection_id,
            client.state.tenant_id,
        )

    def _sanitize_and_serialize_event(self, event: BaseEvent | dict[str, Any]) -> tuple[UUID, str]:
        """Sanitize event payload (stripping passwords, tokens, API keys, raw bodies) and convert to JSON."""
        if isinstance(event, BaseEvent):
            tenant_id = event.tenant_id
            raw_dict = event.model_dump()
            event_type = type(event).__name__
        elif isinstance(event, dict):
            tenant_id = UUID(str(event.get("tenant_id")))
            raw_dict = event.copy()
            event_type = str(raw_dict.get("event_type", "SecurityEvent"))
        else:
            raise ValueError(f"Unsupported event type: {type(event)}")

        # Clean secrets and sensitive PII
        sanitized_dict = sanitize_metadata(raw_dict)
        envelope = {
            "event_type": event_type,
            "timestamp": datetime.now(UTC).isoformat(),
            "payload": sanitized_dict,
        }

        # Custom JSON serializer handling UUIDs, datetimes
        def _json_default(obj: Any) -> str:
            if isinstance(obj, (UUID, datetime)):
                return str(obj)
            return str(obj)

        json_payload = json.dumps(envelope, default=_json_default)
        return tenant_id, json_payload

    async def broadcast_event(self, event: BaseEvent | dict[str, Any]) -> int:
        """Broadcast a sanitized security event strictly to clients of the matching tenant."""
        try:
            tenant_id, json_payload = self._sanitize_and_serialize_event(event)
        except Exception as ser_exc:
            logger.error("Failed to sanitize/serialize event for broadcasting: %s", ser_exc)
            return 0

        async with self._lock:
            target_clients = list(self._clients.get(tenant_id, []))

        if not target_clients:
            return 0

        queued_count = 0
        stale_clients: list[WebSocketClient] = []

        for client in target_clients:
            if not client._is_active:
                stale_clients.append(client)
                continue

            success = client.enqueue_event(json_payload)
            if success:
                queued_count += 1
            else:
                stale_clients.append(client)

        # Cleanup any disconnected or broken clients
        if stale_clients:
            for stale in stale_clients:
                await self.unregister(stale)

        self._total_events_published += 1
        self._total_broadcasts += queued_count
        return queued_count

    async def handle_event(self, event: BaseEvent) -> None:
        """EventBus subscriber callback handler."""
        await self.broadcast_event(event)

    def subscribe_to_event_bus(self, event_bus: Any) -> None:
        """Subscribe the broadcaster to standard enterprise security events on the EventBus."""
        if not hasattr(event_bus, "subscribe"):
            return

        from src.events.ingestion_events import (
            EmailDownloadedEvent,
            IngestionDeadLetteredEvent,
            MailboxConnectedEvent,
            MailboxDisconnectedEvent,
        )
        from src.events.security_events import (
            AnalyticsAggregatedEvent,
            NotificationDispatchedEvent,
            NotificationFailedEvent,
            RemediationExecutedEvent,
            RemediationPendingApprovalEvent,
            RiskScoredEvent,
            ThreatCorrelatedEvent,
        )

        event_classes = [
            RiskScoredEvent,
            ThreatCorrelatedEvent,
            RemediationExecutedEvent,
            RemediationPendingApprovalEvent,
            AnalyticsAggregatedEvent,
            NotificationDispatchedEvent,
            NotificationFailedEvent,
            IngestionDeadLetteredEvent,
            MailboxConnectedEvent,
            MailboxDisconnectedEvent,
            EmailDownloadedEvent,
        ]

        for cls in event_classes:
            try:
                event_bus.subscribe(cls, self.handle_event)
            except Exception as sub_exc:
                logger.warning("Could not subscribe broadcaster to %s: %s", cls.__name__, sub_exc)

    async def _heartbeat_loop(self) -> None:
        """Periodic heartbeat and stale connection cleanup worker."""
        while self._is_running:
            try:
                await asyncio.sleep(self.heartbeat_interval_sec)
                now = datetime.now(UTC)
                stale_clients: list[WebSocketClient] = []

                async with self._lock:
                    all_clients = [c for group in self._clients.values() for c in group]

                for client in all_clients:
                    # Check timeout
                    time_inactive = (now - client.state.last_activity).total_seconds()
                    if time_inactive > self.client_timeout_sec or not client._is_active:
                        stale_clients.append(client)
                    else:
                        # Send ping / keepalive frame
                        ping_json = json.dumps({
                            "event_type": "HEARTBEAT_PING",
                            "timestamp": now.isoformat(),
                        })
                        client.enqueue_event(ping_json)

                for stale in stale_clients:
                    logger.info("Pruning stale WebSocket connection %s", stale.state.connection_id)
                    await self.unregister(stale)

            except asyncio.CancelledError:
                break
            except Exception as hb_exc:
                logger.error("Error in broadcaster heartbeat loop: %s", hb_exc)

    def start(self) -> None:
        """Start the broadcaster and background heartbeat worker."""
        if self._is_running:
            return
        self._is_running = True
        self._heartbeat_task = asyncio.create_task(self._heartbeat_loop())
        logger.info("SOCEventBroadcaster started.")

    async def stop(self) -> None:
        """Gracefully stop broadcaster, cancel heartbeat, and disconnect all clients."""
        if not self._is_running:
            return
        self._is_running = False
        if self._heartbeat_task:
            self._heartbeat_task.cancel()
            try:
                await self._heartbeat_task
            except asyncio.CancelledError:
                pass
            self._heartbeat_task = None

        # Close all active clients
        async with self._lock:
            all_clients = [c for group in self._clients.values() for c in group]
            self._clients.clear()

        for client in all_clients:
            await client.close(code=1001, reason="Server Shutdown")

        logger.info("SOCEventBroadcaster stopped and all client connections closed.")

    def get_stats(self) -> dict[str, Any]:
        """Return global connection and broadcast statistics."""
        total_connections = sum(len(group) for group in self._clients.values())
        return {
            "is_running": self._is_running,
            "total_active_tenants": len(self._clients),
            "total_active_clients": total_connections,
            "total_events_published": self._total_events_published,
            "total_broadcasts_delivered": self._total_broadcasts,
            "max_client_queue": self.max_client_queue,
            "max_clients_per_tenant": self.max_clients_per_tenant,
        }

    def list_client_states(self, tenant_id: UUID | None = None) -> list[dict[str, Any]]:
        """Return diagnostic state for all active clients, optionally filtered by tenant."""
        results: list[dict[str, Any]] = []
        for t_id, group in self._clients.items():
            if tenant_id is None or t_id == tenant_id:
                for c in group:
                    results.append(c.state.model_dump())
        return results


# Global singleton instance for FastAPI dependency injection
_global_broadcaster = SOCEventBroadcaster()


def get_event_broadcaster() -> SOCEventBroadcaster:
    """Dependency provider returning global SOCEventBroadcaster instance."""
    return _global_broadcaster
