"""Provider-agnostic email provider interface protocol for ScamON Enterprise."""

from __future__ import annotations

from typing import Any, Protocol, runtime_checkable


@runtime_checkable
class IEmailProvider(Protocol):
    """Protocol defining common interface for all email ingestion providers (Gmail, MS Graph)."""

    @property
    def provider_name(self) -> str:
        """Name of the ingestion provider (e.g. 'GMAIL', 'MS_GRAPH')."""
        ...

    async def authenticate(self, auth_code: str | None = None) -> dict[str, Any]:
        """Exchange authorization code for OAuth2 tokens."""
        ...

    async def refresh_tokens(self, refresh_token: str) -> dict[str, Any]:
        """Refresh expired OAuth2 access tokens."""
        ...

    async def setup_watch(self, webhook_url: str) -> dict[str, Any]:
        """Configure push notifications / watch subscription for real-time mailbox events."""
        ...

    async def stop_watch(self) -> bool:
        """Stop real-time push notification watch subscription."""
        ...

    async def fetch_initial_sync(self, limit: int = 50) -> list[dict[str, Any]]:
        """Perform initial mailbox synchronization, fetching recent message summaries."""
        ...

    async def fetch_incremental_sync(
        self, history_id: str | int
    ) -> list[dict[str, Any]]:
        """Perform incremental synchronization using provider History / Delta API."""
        ...

    async def get_raw_eml(self, message_id: str) -> bytes:
        """Fetch raw RFC 5322 EML byte payload for a message ID."""
        ...

    async def get_message_metadata(self, message_id: str) -> dict[str, Any]:
        """Fetch parsed envelope metadata (headers, sender, recipient, subject)."""
        ...

    async def list_attachments(self, message_id: str) -> list[dict[str, Any]]:
        """List attachment metadata summaries for a message."""
        ...
