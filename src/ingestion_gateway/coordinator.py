"""Dynamic Account Sync Coordinator for Mailbox Ingestion Gateway (Module 22)."""

from __future__ import annotations

import asyncio
import hashlib
import time
from collections.abc import Callable
from datetime import UTC, datetime
from typing import Any
from uuid import UUID

from src.config.enterprise_config import settings
from src.ingestion_gateway.manager import IngestionGatewayManager
from src.ingestion_gateway.models import MailboxProvider
from src.utils.logging import get_logger

logger = get_logger(__name__)


class AccountSyncCoordinator:
    """Asynchronous background coordinator reconciling active database EmailAccount entities

    with registered live mailbox provider daemons inside MailboxDaemonRegistry.
    """

    def __init__(
        self,
        manager: IngestionGatewayManager,
        account_repo: Any,
        sync_interval_sec: float | None = None,
    ) -> None:
        self.manager = manager
        self.account_repo = account_repo
        self.sync_interval_sec = (
            sync_interval_sec
            if sync_interval_sec is not None
            else float(settings.account_sync_interval_sec)
        )
        self._is_running = False
        self._task: asyncio.Task[None] | None = None
        self._lock = asyncio.Lock()

        # Telemetry & Backoff State: Key is (tenant_id, account_id)
        self._consecutive_failures: dict[tuple[UUID, UUID], int] = {}
        self._next_retry_time: dict[tuple[UUID, UUID], float] = {}
        self._account_config_hashes: dict[tuple[UUID, UUID], str] = {}
        self._last_sync_time: datetime | None = None
        self._total_sync_cycles: int = 0
        self._total_daemons_spawned: int = 0
        self._total_daemons_terminated: int = 0

    @property
    def is_running(self) -> bool:
        """Return True if background sync loop is active."""
        return self._is_running

    def _compute_config_hash(self, account: Any) -> str:
        """Generate SHA-256 fingerprint of account authentication & config parameters."""
        raw_repr = (
            f"{getattr(account, 'provider', '')}:"
            f"{getattr(account, 'email_address', '')}:"
            f"{getattr(account, 'access_token', '')}:"
            f"{getattr(account, 'refresh_token', '')}"
        )
        return hashlib.sha256(raw_repr.encode("utf-8")).hexdigest()

    def _map_provider(self, provider_val: Any) -> MailboxProvider:
        """Map raw provider string or enum to MailboxProvider enum safely."""
        if isinstance(provider_val, MailboxProvider):
            return provider_val
        val_str = str(provider_val).upper().strip()
        if "GRAPH" in val_str or "MICROSOFT" in val_str or "OFFICE" in val_str:
            return MailboxProvider.MS_GRAPH
        if "GMAIL" in val_str or "GOOGLE" in val_str:
            return MailboxProvider.GMAIL
        if "IMAP" in val_str:
            return MailboxProvider.IMAP
        raise ValueError(f"Unknown mailbox provider type: {provider_val}")

    def _calculate_backoff_sec(self, failures: int) -> float:
        """Calculate exponential backoff: 10s, 20s, 40s, 80s, 160s, max 300s."""
        if failures <= 0:
            return 0.0
        return min(10.0 * (2.0 ** (failures - 1)), 300.0)

    async def _fetch_accounts(self) -> list[Any]:
        """Query accounts from repository or callable provider asynchronously."""
        if callable(self.account_repo):
            res = self.account_repo()
            if asyncio.iscoroutine(res):
                return await res
            return res

        if hasattr(self.account_repo, "list_all"):
            res = self.account_repo.list_all()
            if asyncio.iscoroutine(res):
                return await res
            return res

        if hasattr(self.account_repo, "get_all"):
            res = self.account_repo.get_all()
            if asyncio.iscoroutine(res):
                return await res
            return res

        return []

    async def reconcile_once(self) -> dict[str, Any]:
        """Perform a single, thread-safe reconciliation sweep between database accounts and daemons."""
        async with self._lock:
            all_accounts = await self._fetch_accounts()
            # Filter active accounts strictly
            active_accounts = [
                acc for acc in all_accounts if getattr(acc, "is_active", True)
            ]
            active_keys = {(acc.tenant_id, acc.id) for acc in active_accounts}
            now = time.monotonic()

            # 1. Terminate & unregister daemons whose accounts were deactivated or deleted
            current_daemons = self.manager.registry.list_daemons()
            for daemon in current_daemons:
                daemon_key = (daemon.tenant_id, daemon.account_id)
                if daemon_key not in active_keys:
                    logger.info(
                        "Deactivating daemon for inactive/removed account %s (Tenant %s)",
                        daemon.account_id,
                        daemon.tenant_id,
                    )
                    try:
                        await daemon.stop()
                    except Exception as stop_exc:
                        logger.warning("Error stopping daemon %s: %s", daemon_key, stop_exc)

                    self.manager.registry.unregister(
                        daemon.tenant_id, daemon.account_id, daemon.provider
                    )
                    self._consecutive_failures.pop(daemon_key, None)
                    self._next_retry_time.pop(daemon_key, None)
                    self._account_config_hashes.pop(daemon_key, None)
                    self._total_daemons_terminated += 1

            # 2. Reconcile active accounts (Spawn new or Reconfigure changed)
            for acc in active_accounts:
                acc_key = (acc.tenant_id, acc.id)

                # Check backoff window
                if acc_key in self._next_retry_time and now < self._next_retry_time[acc_key]:
                    continue

                try:
                    provider = self._map_provider(acc.provider)
                    cfg_hash = self._compute_config_hash(acc)
                    existing_daemon = self.manager.registry.get_daemon(
                        acc.tenant_id, acc.id, provider
                    )

                    if existing_daemon is None:
                        # Account added: Spawn & Start new daemon
                        daemon = self.manager.create_and_register_daemon(
                            tenant_id=acc.tenant_id,
                            account_id=acc.id,
                            mailbox_address=acc.email_address,
                            provider=provider,
                        )
                        await daemon.start()
                        self._account_config_hashes[acc_key] = cfg_hash
                        self._consecutive_failures.pop(acc_key, None)
                        self._next_retry_time.pop(acc_key, None)
                        self._total_daemons_spawned += 1
                        logger.info(
                            "Spawned live %s daemon for %s (Tenant %s, Account %s)",
                            provider.value,
                            acc.email_address,
                            acc.tenant_id,
                            acc.id,
                        )
                    else:
                        # Account already running: Check for config/credential change
                        stored_hash = self._account_config_hashes.get(acc_key)
                        if stored_hash and stored_hash != cfg_hash:
                            logger.info(
                                "Config update detected for account %s. Restarting daemon.",
                                acc.id,
                            )
                            await existing_daemon.stop()
                            self.manager.registry.unregister(
                                acc.tenant_id, acc.id, provider
                            )
                            new_daemon = self.manager.create_and_register_daemon(
                                tenant_id=acc.tenant_id,
                                account_id=acc.id,
                                mailbox_address=acc.email_address,
                                provider=provider,
                            )
                            await new_daemon.start()
                            self._account_config_hashes[acc_key] = cfg_hash
                            self._consecutive_failures.pop(acc_key, None)
                            self._next_retry_time.pop(acc_key, None)

                except Exception as exc:
                    # Clean up failed daemon from registry if it was registered
                    try:
                        provider = self._map_provider(acc.provider)
                        self.manager.registry.unregister(acc.tenant_id, acc.id, provider)
                    except Exception:
                        pass

                    # Isolate failure to this specific account
                    current_fails = self._consecutive_failures.get(acc_key, 0) + 1
                    self._consecutive_failures[acc_key] = current_fails
                    backoff = self._calculate_backoff_sec(current_fails)
                    self._next_retry_time[acc_key] = now + backoff

                    logger.error(
                        "Failed to reconcile mailbox daemon for account %s (attempt %d, backoff %.1fs): %s",
                        acc.id,
                        current_fails,
                        backoff,
                        exc,
                    )

            self._last_sync_time = datetime.now(UTC)
            self._total_sync_cycles += 1

            return {
                "sync_cycles": self._total_sync_cycles,
                "active_accounts": len(active_accounts),
                "active_daemons": len(self.manager.registry.list_daemons()),
                "total_spawned": self._total_daemons_spawned,
                "total_terminated": self._total_daemons_terminated,
                "backoff_accounts": len(self._next_retry_time),
            }

    async def _sync_loop(self) -> None:
        """Internal background polling loop executing periodic reconciliation."""
        logger.info(
            "Starting AccountSyncCoordinator loop (interval: %.1fs)",
            self.sync_interval_sec,
        )
        while self._is_running:
            try:
                await self.reconcile_once()
            except asyncio.CancelledError:
                break
            except Exception as loop_exc:
                logger.error("Unexpected error in AccountSyncCoordinator loop: %s", loop_exc)

            try:
                await asyncio.sleep(self.sync_interval_sec)
            except asyncio.CancelledError:
                break

    def start(self) -> None:
        """Start the background synchronization coordinator task."""
        if self._is_running:
            return
        self._is_running = True
        self._task = asyncio.create_task(self._sync_loop())

    async def stop(self) -> None:
        """Gracefully stop the background synchronization coordinator task."""
        if not self._is_running:
            return
        self._is_running = False
        if self._task:
            self._task.cancel()
            try:
                await self._task
            except asyncio.CancelledError:
                pass
            self._task = None
        logger.info("AccountSyncCoordinator stopped.")

    def health_check(self) -> dict[str, Any]:
        """Return operational health status and metrics."""
        has_failures = len(self._consecutive_failures) > 0
        status_str = "HEALTHY"
        if not self._is_running:
            status_str = "STOPPED"
        elif has_failures:
            status_str = "DEGRADED"

        return {
            "status": status_str,
            "sync_interval_sec": self.sync_interval_sec,
            "total_sync_cycles": self._total_sync_cycles,
            "total_daemons_spawned": self._total_daemons_spawned,
            "total_daemons_terminated": self._total_daemons_terminated,
            "active_daemons_count": len(self.manager.registry.list_daemons()),
            "failed_accounts_in_backoff": len(self._next_retry_time),
            "last_sync_time": (
                self._last_sync_time.isoformat() if self._last_sync_time else None
            ),
        }

    def get_state(self) -> dict[str, Any]:
        """Return diagnostic state snapshot."""
        return {
            "is_running": self._is_running,
            "sync_interval_sec": self.sync_interval_sec,
            "total_sync_cycles": self._total_sync_cycles,
            "consecutive_failures": {
                f"{t_id}:{a_id}": count
                for (t_id, a_id), count in self._consecutive_failures.items()
            },
            "registered_daemons": [
                {
                    "tenant_id": str(d.tenant_id),
                    "account_id": str(d.account_id),
                    "provider": d.provider.value,
                    "mailbox": d.mailbox_address,
                }
                for d in self.manager.registry.list_daemons()
            ],
        }
