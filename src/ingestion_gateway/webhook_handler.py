"""FastAPI Webhook Router and Daemon Registry for Ingestion Gateway (Module 21)."""

from __future__ import annotations

import hmac
import json
import threading
from typing import Any
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Query, Request, Response, status

from src.ingestion_gateway.dead_letter import DeadLetterQueue
from src.ingestion_gateway.exceptions import (
    AuthenticationFailedError,
    PayloadSizeExceededError,
)
from src.ingestion_gateway.models import MailboxProvider
from src.ingestion_gateway.providers.base import IAsyncMailboxDaemon
from src.ingestion_gateway.providers.gmail_daemon import GmailIngestionDaemon
from src.ingestion_gateway.providers.msgraph_daemon import MSGraphIngestionDaemon
from src.utils.logging import get_logger

logger = get_logger(__name__)


class MailboxDaemonRegistry:
    """Thread-safe, multi-tenant registry for routing webhooks to active mailbox daemons."""

    def __init__(self) -> None:
        self._lock = threading.RLock()
        # Key: (tenant_id, account_id, provider) -> IAsyncMailboxDaemon
        self._daemons_by_id: dict[tuple[UUID, UUID, MailboxProvider], IAsyncMailboxDaemon] = {}
        # Key: (provider, mailbox_address.lower()) -> IAsyncMailboxDaemon
        self._daemons_by_mailbox: dict[tuple[MailboxProvider, str], IAsyncMailboxDaemon] = {}

    def register(self, daemon: IAsyncMailboxDaemon) -> None:
        """Register an active daemon worker into the registry."""
        with self._lock:
            key_id = (daemon.tenant_id, daemon.account_id, daemon.provider)
            key_mb = (daemon.provider, daemon.mailbox_address.lower())
            self._daemons_by_id[key_id] = daemon
            self._daemons_by_mailbox[key_mb] = daemon
            logger.info(
                "Registered %s daemon for mailbox %s (Tenant %s, Account %s)",
                daemon.provider.value,
                daemon.mailbox_address,
                daemon.tenant_id,
                daemon.account_id,
            )

    def unregister(
        self, tenant_id: UUID, account_id: UUID, provider: MailboxProvider
    ) -> bool:
        """Unregister an active daemon worker."""
        with self._lock:
            key_id = (tenant_id, account_id, provider)
            daemon = self._daemons_by_id.pop(key_id, None)
            if daemon:
                key_mb = (provider, daemon.mailbox_address.lower())
                self._daemons_by_mailbox.pop(key_mb, None)
                return True
            return False

    def get_daemon(
        self, tenant_id: UUID, account_id: UUID, provider: MailboxProvider
    ) -> IAsyncMailboxDaemon | None:
        """Retrieve a daemon strictly scoped by tenant UUID, account UUID, and provider."""
        with self._lock:
            return self._daemons_by_id.get((tenant_id, account_id, provider))

    def find_daemon_by_mailbox(
        self, provider: MailboxProvider, mailbox_address: str
    ) -> IAsyncMailboxDaemon | None:
        """Retrieve a daemon by provider and mailbox address."""
        with self._lock:
            return self._daemons_by_mailbox.get((provider, mailbox_address.lower()))

    def list_daemons(
        self, tenant_id: UUID | None = None
    ) -> list[IAsyncMailboxDaemon]:
        """List all active registered daemons, optionally filtered by tenant."""
        with self._lock:
            if tenant_id is None:
                return list(self._daemons_by_id.values())
            return [d for d in self._daemons_by_id.values() if d.tenant_id == tenant_id]

    def clear(self) -> None:
        """Clear all registered daemons."""
        with self._lock:
            self._daemons_by_id.clear()
            self._daemons_by_mailbox.clear()


# Global singletons for FastAPI dependency injection
_global_registry = MailboxDaemonRegistry()
_global_dlq = DeadLetterQueue()


def get_daemon_registry() -> MailboxDaemonRegistry:
    """FastAPI dependency provider for the MailboxDaemonRegistry."""
    return _global_registry


def get_dead_letter_queue() -> DeadLetterQueue:
    """FastAPI dependency provider for the DeadLetterQueue."""
    return _global_dlq


# =============================================================================
# FastAPI APIRouter Definition
# =============================================================================
ingestion_webhook_router = APIRouter(
    prefix="/api/v1/ingestion/webhooks",
    tags=["Ingestion Webhooks"],
)


@ingestion_webhook_router.post("/msgraph")
async def msgraph_webhook_endpoint(
    request: Request,
    validation_token: str | None = Query(default=None, alias="validationToken"),
    registry: MailboxDaemonRegistry = Depends(get_daemon_registry),
    dlq: DeadLetterQueue = Depends(get_dead_letter_queue),
) -> Any:
    """Microsoft Graph change notification webhook endpoint.

    Handles Microsoft Graph validationToken handshake (echoed back as text/plain)
    and routes change notifications to registered MSGraphIngestionDaemon instances.
    """
    # 1. Handle Graph Validation Handshake
    if validation_token:
        logger.info("Received Microsoft Graph webhook validation handshake.")
        return Response(
            content=validation_token,
            media_type="text/plain; charset=utf-8",
            status_code=status.HTTP_200_OK,
        )

    # 2. Parse & Validate Notification Body
    try:
        body = await request.json()
    except Exception as exc:
        logger.warning("Malformed JSON in Microsoft Graph webhook body: %s", exc)
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Malformed JSON payload",
        ) from exc

    if not isinstance(body, dict) or "value" not in body or not isinstance(body["value"], list):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid notification envelope: missing 'value' array",
        )

    total_processed = 0
    notifications = body["value"]

    # 3. Route Notifications to Registered Daemons
    for item in notifications:
        if not isinstance(item, dict):
            continue

        # In Graph notifications, subscriptionId or clientState or target daemons are matched
        daemons = registry.list_daemons()
        graph_daemons = [d for d in daemons if isinstance(d, MSGraphIngestionDaemon)]

        if not graph_daemons:
            logger.warning("No active MSGraphIngestionDaemon found to handle notification.")
            continue

        for daemon in graph_daemons:
            # Check clientState match
            received_state = item.get("clientState")
            if daemon.client_state and not hmac.compare_digest(daemon.client_state, received_state or ""):
                # Skip daemons that do not match this notification's clientState
                continue

            try:
                ingested = await daemon.process_notification({"value": [item]})
                total_processed += len(ingested)
            except AuthenticationFailedError as auth_exc:
                logger.warning("Authentication failed during Graph notification processing: %s", auth_exc)
                raise HTTPException(
                    status_code=status.HTTP_401_UNAUTHORIZED,
                    detail="Invalid notification clientState",
                ) from auth_exc
            except PayloadSizeExceededError as size_exc:
                # Quarantined into DLQ
                dlq.enqueue(
                    tenant_id=daemon.tenant_id,
                    account_id=daemon.account_id,
                    provider=MailboxProvider.MS_GRAPH,
                    reason="PAYLOAD_SIZE_EXCEEDED",
                    error_message=str(size_exc),
                    provider_message_id=item.get("resourceData", {}).get("id"),
                    raw_payload=json.dumps(item),
                )
                raise HTTPException(
                    status_code=status.HTTP_422_UNPROCESSABLE_CONTENT,
                    detail=str(size_exc),
                ) from size_exc
            except Exception as proc_exc:
                logger.error("Unhandled error processing Graph notification: %s", proc_exc)
                dlq.enqueue(
                    tenant_id=daemon.tenant_id,
                    account_id=daemon.account_id,
                    provider=MailboxProvider.MS_GRAPH,
                    reason="PROCESSING_FAILURE",
                    error_message=str(proc_exc),
                    provider_message_id=item.get("resourceData", {}).get("id"),
                    raw_payload=json.dumps(item),
                )
                raise HTTPException(
                    status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                    detail="Failed to process Graph notification",
                ) from proc_exc

    return {"status": "accepted", "processed_count": total_processed}


@ingestion_webhook_router.post("/gmail")
async def gmail_pubsub_webhook_endpoint(
    request: Request,
    verification_token: str | None = Query(default=None, alias="token"),
    registry: MailboxDaemonRegistry = Depends(get_daemon_registry),
    dlq: DeadLetterQueue = Depends(get_dead_letter_queue),
) -> Any:
    """Google Cloud Pub/Sub push notification webhook endpoint.

    Validates Pub/Sub message envelope, verifies optional token, and routes to
    the matching GmailIngestionDaemon instance.
    """
    # 1. Parse JSON Body
    try:
        body = await request.json()
    except Exception as exc:
        logger.warning("Malformed JSON in Gmail Pub/Sub webhook body: %s", exc)
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Malformed JSON payload",
        ) from exc

    if not isinstance(body, dict) or "message" not in body or not isinstance(body["message"], dict):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid Pub/Sub envelope: missing 'message' object",
        )

    # 2. Find Registered Gmail Daemons
    daemons = registry.list_daemons()
    gmail_daemons = [d for d in daemons if isinstance(d, GmailIngestionDaemon)]

    if not gmail_daemons:
        logger.warning("No active GmailIngestionDaemon registered.")
        return Response(status_code=status.HTTP_204_NO_CONTENT)

    total_processed = 0

    for daemon in gmail_daemons:
        # Token validation if configured
        if daemon.verification_token:
            if not verification_token or not hmac.compare_digest(daemon.verification_token, verification_token):
                logger.warning("Invalid verification token for Gmail daemon on %s", daemon.mailbox_address)
                raise HTTPException(
                    status_code=status.HTTP_401_UNAUTHORIZED,
                    detail="Invalid verification token",
                )

        try:
            ingested = await daemon.process_pubsub_envelope(body)
            total_processed += len(ingested)
        except Exception as proc_exc:
            logger.error("Unhandled error processing Gmail Pub/Sub notification: %s", proc_exc)
            dlq.enqueue(
                tenant_id=daemon.tenant_id,
                account_id=daemon.account_id,
                provider=MailboxProvider.GMAIL,
                reason="PROCESSING_FAILURE",
                error_message=str(proc_exc),
                raw_payload=json.dumps(body),
            )
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="Failed to process Gmail Pub/Sub message",
            ) from proc_exc

    return {"status": "accepted", "processed_count": total_processed}
