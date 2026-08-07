"""Ingestion provider implementations package."""

from __future__ import annotations

from src.ingestion.providers.gmail_provider import GmailProvider
from src.ingestion.providers.msgraph_provider import MicrosoftGraphProvider

__all__ = [
    "GmailProvider",
    "MicrosoftGraphProvider",
]
