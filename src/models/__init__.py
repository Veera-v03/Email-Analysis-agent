"""Strict data contracts used by the application."""

from src.models.config import ApplicationConfig
from src.models.email import EmailAttachment, EmailHeader, EmailInput
from src.models.sender import ParsedEmailAddress, SenderAnalysisResult

__all__ = [
    "ApplicationConfig",
    "EmailAttachment",
    "EmailHeader",
    "EmailInput",
    "ParsedEmailAddress",
    "SenderAnalysisResult",
]
