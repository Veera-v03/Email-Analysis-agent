"""Sanitization, secret redaction, and markup normalization for retrieved memory."""

from __future__ import annotations

import html
import re
from typing import ClassVar


class ContentSanitizer:
    """Sanitizes text and redacts credentials before RAG context construction."""

    # Regex patterns for credential and secret redaction
    SECRET_PATTERNS: ClassVar[list[tuple[re.Pattern[str], str]]] = [
        (re.compile(r"(?i)bearer\s+[a-zA-Z0-9_\-\.]{16,}"), "Bearer [REDACTED_TOKEN]"),
        (re.compile(r"(?i)\bauthorization:\s*(?:basic|bearer)?\s*[a-zA-Z0-9_\-\.=:]{8,}"), "Authorization: [REDACTED_HEADER]"),
        (re.compile(r"(?i)\b(?:sk|pk|api|key)_[a-zA-Z0-9_\-]{16,}\b"), "[REDACTED_API_KEY]"),
        (re.compile(r"\bAIza[0-9A-Za-z\-_]{35}\b"), "[REDACTED_GOOGLE_API_KEY]"),
        (re.compile(r"\beyJ[a-zA-Z0-9_\-]{10,}\.[a-zA-Z0-9_\-]{10,}\.[a-zA-Z0-9_\-]{10,}\b"), "[REDACTED_JWT]"),
        (re.compile(r"(?i)(?:password|passwd|secret)\s*[:=]\s*['\"][^'\"]+['\"]"), "password=[REDACTED_SECRET]"),
    ]

    # Pattern for removing non-printable/control characters (except newline, tab)
    CONTROL_CHARS_PATTERN: ClassVar[re.Pattern[str]] = re.compile(r"[\x00-\x08\x0B\x0C\x0E-\x1F\x7F-\x9F]")

    @classmethod
    def sanitize(cls, text: str, max_length: int = 800) -> str:
        """Sanitize text: remove control chars, redact secrets, escape markup, and truncate."""
        if not text:
            return ""

        # 1. Remove non-printable / control characters
        cleaned = cls.CONTROL_CHARS_PATTERN.sub("", text)

        # 2. Redact sensitive credentials
        for pattern, replacement in cls.SECRET_PATTERNS:
            cleaned = pattern.sub(replacement, cleaned)

        # 3. Normalize excessive whitespace
        cleaned = re.sub(r"\s+", " ", cleaned).strip()

        # 4. XML / HTML escaping to prevent delimiter injection
        cleaned = html.escape(cleaned, quote=True)

        # 5. Deterministic length truncation
        if len(cleaned) > max_length:
            cleaned = cleaned[:max_length] + " [TRUNCATED]"

        return cleaned
