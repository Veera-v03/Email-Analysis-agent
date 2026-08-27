"""PII and sensitive data sanitization utility for notification payloads."""

from __future__ import annotations

import re
from typing import Any

from src.notifications.models import NotificationPayloadDTO

# Sensitive keyword pattern replacements (pattern, replacement string)
SENSITIVE_KEYWORD_PATTERNS: list[tuple[re.Pattern[str], str]] = [
    (re.compile(r"(?i)(bearer\s+)[a-zA-Z0-9_\-\.]{10,}", re.IGNORECASE), r"\1[REDACTED]"),
    (re.compile(r"(?i)(password|passwd|pwd)(\s*[:=]\s*['\"]?)[^\s,'\"]+(['\"]?)", re.IGNORECASE), r"\1\2[REDACTED]\3"),
    (re.compile(r"(?i)(api[_-]?key|secret|token)(\s*[:=]\s*['\"]?)[^\s,'\"]+(['\"]?)", re.IGNORECASE), r"\1\2[REDACTED]\3"),
    (re.compile(r"(?i)(authorization:\s*bearer\s+)\S+", re.IGNORECASE), r"\1[REDACTED]"),
    (re.compile(r"sk-[a-zA-Z0-9]{20,}", re.IGNORECASE), "[REDACTED]"),
    (re.compile(r"gsk_[a-zA-Z0-9]{20,}", re.IGNORECASE), "[REDACTED]"),
]

# Sensitive dictionary keys that should be redacted completely or replaced
SENSITIVE_KEYS: set[str] = {
    "password",
    "password_hash",
    "secret",
    "secret_key",
    "api_key",
    "token",
    "access_token",
    "refresh_token",
    "auth_header",
    "authorization",
    "raw_body",
    "raw_eml",
    "raw_content",
    "body_html",
    "body_text",
    "client_secret",
    "private_key",
}


def sanitize_text(text: str) -> str:
    """Sanitize a text string by redacting detected tokens, credentials, and API keys."""
    if not text:
        return text

    sanitized = text
    for pattern, repl in SENSITIVE_KEYWORD_PATTERNS:
        sanitized = pattern.sub(repl, sanitized)

    return sanitized


def sanitize_metadata(data: Any) -> Any:
    """Recursively sanitize dictionary or list metadata removing secrets and raw payloads."""
    if isinstance(data, dict):
        cleaned: dict[str, Any] = {}
        for k, v in data.items():
            k_lower = str(k).lower()
            if k_lower in SENSITIVE_KEYS:
                cleaned[str(k)] = "[REDACTED]"
            elif isinstance(v, (dict, list)):
                cleaned[str(k)] = sanitize_metadata(v)
            elif isinstance(v, str):
                cleaned[str(k)] = sanitize_text(v)
            else:
                cleaned[str(k)] = v
        return cleaned

    if isinstance(data, list):
        return [sanitize_metadata(item) for item in data]

    if isinstance(data, str):
        return sanitize_text(data)

    return data


def sanitize_payload(payload: NotificationPayloadDTO) -> NotificationPayloadDTO:
    """Return a sanitized copy of NotificationPayloadDTO."""
    sanitized_message = sanitize_text(payload.message)
    sanitized_title = sanitize_text(payload.title)
    sanitized_meta = sanitize_metadata(payload.metadata)

    return NotificationPayloadDTO(
        notification_id=payload.notification_id,
        tenant_id=payload.tenant_id,
        event_name=payload.event_name,
        title=sanitized_title,
        message=sanitized_message,
        priority=payload.priority,
        incident_id=payload.incident_id,
        message_id=payload.message_id,
        metadata=sanitized_meta,
        timestamp=payload.timestamp,
    )
