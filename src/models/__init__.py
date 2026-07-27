"""Strict data contracts used by the application."""

from src.models.config import ApplicationConfig
from src.models.email import EmailAttachment, EmailHeader, EmailInput

__all__ = [
    "ApplicationConfig",
    "EmailAttachment",
    "EmailHeader",
    "EmailInput",
]
