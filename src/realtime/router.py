"""FastAPI WebSocket router for Real-Time SOC security event streaming (Module 22)."""

from __future__ import annotations

import asyncio
from uuid import UUID

from fastapi import APIRouter, Depends, Query, WebSocket, WebSocketDisconnect, status

from src.realtime.broadcaster import (
    SOCEventBroadcaster,
    WebSocketClient,
    get_event_broadcaster,
)
from src.security.auth import decode_jwt_token
from src.utils.logging import get_logger

logger = get_logger(__name__)

realtime_router = APIRouter(prefix="/api/v1/realtime", tags=["realtime"])


@realtime_router.websocket("/soc")
async def soc_event_websocket_endpoint(
    websocket: WebSocket,
    token: str | None = Query(default=None, description="JWT Authentication Bearer Token"),
    tenant_id: str | None = Query(default=None, description="Target Tenant UUID parameter"),
    broadcaster: SOCEventBroadcaster = Depends(get_event_broadcaster),
) -> None:
    """Authenticated, tenant-isolated WebSocket endpoint streaming real-time security events to SOC dashboards."""
    await websocket.accept()

    # 1. Authenticate WebSocket Connection
    if not token:
        logger.warning("Rejecting unauthenticated WebSocket connection: missing token")
        await websocket.close(
            code=status.WS_1008_POLICY_VIOLATION, reason="Missing authentication token"
        )
        return

    try:
        claims = decode_jwt_token(token)
    except Exception as auth_exc:
        logger.warning("Rejecting invalid/expired WebSocket token: %s", auth_exc)
        await websocket.close(
            code=status.WS_1008_POLICY_VIOLATION, reason="Invalid authentication token"
        )
        return

    # 2. Extract and Validate Tenant Boundary
    token_tenant_id_str = claims.get("tenant_id") or claims.get("org_id")
    if not token_tenant_id_str:
        logger.warning("Rejecting WebSocket token missing tenant_id claim")
        await websocket.close(
            code=status.WS_1008_POLICY_VIOLATION, reason="Missing tenant identity claim"
        )
        return

    try:
        authenticated_tenant_id = UUID(str(token_tenant_id_str))
    except ValueError:
        await websocket.close(
            code=status.WS_1008_POLICY_VIOLATION, reason="Malformed tenant identity"
        )
        return

    # If explicit tenant_id query is provided, verify match (prevent cross-tenant hijacking)
    if tenant_id:
        try:
            requested_tenant_id = UUID(str(tenant_id))
            roles = claims.get("roles", [])
            is_super_admin = "SUPER_ADMIN" in roles or "SYSTEM_ADMIN" in roles
            if requested_tenant_id != authenticated_tenant_id and not is_super_admin:
                logger.warning(
                    "Cross-tenant WebSocket request denied: token tenant %s != query tenant %s",
                    authenticated_tenant_id,
                    requested_tenant_id,
                )
                await websocket.close(
                    code=status.WS_1008_POLICY_VIOLATION, reason="Cross-tenant access forbidden"
                )
                return
            target_tenant = requested_tenant_id if is_super_admin else authenticated_tenant_id
        except ValueError:
            await websocket.close(
                code=status.WS_1008_POLICY_VIOLATION, reason="Malformed query tenant_id"
            )
            return
    else:
        target_tenant = authenticated_tenant_id

    # 3. Extract User Identity
    user_id_str = claims.get("sub") or claims.get("user_id")
    user_id: UUID | None = None
    if user_id_str:
        try:
            user_id = UUID(str(user_id_str))
        except ValueError:
            pass

    # 4. Instantiate & Register WebSocket Client Session
    client = WebSocketClient(
        websocket=websocket,
        tenant_id=target_tenant,
        user_id=user_id,
        max_queue_size=broadcaster.max_client_queue,
    )

    registered = await broadcaster.register(client)
    if not registered:
        await websocket.close(
            code=status.WS_1008_POLICY_VIOLATION,
            reason="Max concurrent client connections reached for tenant",
        )
        return

    # 5. Receive Frame Loop (Heartbeat Acks / Client Pings)
    try:
        while client._is_active:
            # Wait for client frames (ping/pong or text)
            try:
                data = await websocket.receive_text()
                if data:
                    client.state.last_activity = client.state.last_activity
            except (WebSocketDisconnect, RuntimeError):
                break
            except asyncio.CancelledError:
                break
    finally:
        await broadcaster.unregister(client)
