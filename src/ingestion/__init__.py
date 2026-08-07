"""Email Ingestion Platform package for ScamON Enterprise."""

from __future__ import annotations

from src.ingestion.exceptions import (
    IngestionError,
    MailboxSyncError,
    ProviderAuthenticationError,
    ProviderQuotaExceededError,
)
from src.ingestion.interfaces import IEmailProvider
from src.ingestion.module import IngestionModule, register_ingestion_module
from src.ingestion.pipeline import IngestionPipeline
from src.ingestion.providers.gmail_provider import GmailProvider
from src.ingestion.providers.msgraph_provider import MicrosoftGraphProvider

__all__ = [
    "GmailProvider",
    "IEmailProvider",
    "IngestionError",
    "IngestionModule",
    "IngestionPipeline",
    "MailboxSyncError",
    "MicrosoftGraphProvider",
    "ProviderAuthenticationError",
    "ProviderQuotaExceededError",
    "register_ingestion_module",
]
