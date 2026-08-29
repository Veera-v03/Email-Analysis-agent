"""Mailbox provider daemon interfaces and concrete exports."""

from __future__ import annotations

from src.ingestion_gateway.providers.base import (
    DeliveryHandler,
    IAsyncMailboxDaemon,
)
from src.ingestion_gateway.providers.gmail_daemon import GmailIngestionDaemon
from src.ingestion_gateway.providers.imap_daemon import IMAPIngestionDaemon
from src.ingestion_gateway.providers.msgraph_daemon import MSGraphIngestionDaemon

__all__ = [
    "IAsyncMailboxDaemon",
    "DeliveryHandler",
    "MSGraphIngestionDaemon",
    "GmailIngestionDaemon",
    "IMAPIngestionDaemon",
]
