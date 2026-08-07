"""Recursive MIME tree walker and content collector with depth recursion limiting."""

from __future__ import annotations

from email.message import Message

from src.parsing.body.charset_detector import decode_bytes_to_utf8
from src.parsing.body.unicode_cleaner import normalize_unicode_nfkc

MAX_RECURSION_DEPTH = 20


class MimePartContent:
    """Container for collected text/plain and text/html MIME body parts."""

    def __init__(self) -> None:
        self.plain_parts: list[str] = []
        self.html_parts: list[str] = []
        self.attachments_raw: list[Message] = []


def walk_mime_tree(
    msg: Message, depth: int = 0, collector: MimePartContent | None = None
) -> MimePartContent:
    """Recursively walk email MIME tree up to MAX_RECURSION_DEPTH."""
    if collector is None:
        collector = MimePartContent()

    if depth > MAX_RECURSION_DEPTH:
        return collector

    if msg.is_multipart():
        for part in msg.get_payload():
            if isinstance(part, Message):
                walk_mime_tree(part, depth + 1, collector)
    else:
        content_type = msg.get_content_type().lower()
        disposition = str(msg.get("Content-Disposition", "")).lower()

        # Check if part is an attachment
        if "attachment" in disposition or msg.get_filename():
            collector.attachments_raw.append(msg)
        elif content_type == "text/plain":
            payload = msg.get_payload(decode=True)
            if isinstance(payload, bytes):
                charset = msg.get_content_charset()
                text = decode_bytes_to_utf8(payload, declared_charset=charset)
                collector.plain_parts.append(text)
        elif content_type == "text/html":
            payload = msg.get_payload(decode=True)
            if isinstance(payload, bytes):
                charset = msg.get_content_charset()
                text = decode_bytes_to_utf8(payload, declared_charset=charset)
                collector.html_parts.append(text)
        elif "image/" in content_type or "application/" in content_type:
            collector.attachments_raw.append(msg)

    return collector
