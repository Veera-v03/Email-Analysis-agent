"""Attachment payload extraction, magic-bytes verification, SHA-256/MD5 hashing, and path sanitization."""

from __future__ import annotations

import hashlib
from email.message import Message
from pathlib import Path

from src.parsing.headers.header_parser import decode_rfc2047_header
from src.parsing.models import ExtractedAttachmentDTO

# Magic bytes signature dictionary for MIME detection fallback
MAGIC_SIGNATURES: list[tuple[bytes, str]] = [
    (b"\x89PNG\r\n\x1a\n", "image/png"),
    (b"\xff\xd8\xff", "image/jpeg"),
    (b"GIF87a", "image/gif"),
    (b"GIF89a", "image/gif"),
    (b"%PDF", "application/pdf"),
    (b"PK\x03\x04", "application/zip"),
    (b"MZ", "application/x-dsexec"),  # Windows PE executable
    (b"\xd0\xcf\x11\xe0", "application/msword"),  # OLE Compound File
]

DANGEROUS_EXTENSIONS = {
    ".exe",
    ".dll",
    ".bat",
    ".cmd",
    ".ps1",
    ".vbs",
    ".js",
    ".jar",
    ".scr",
    ".pif",
    ".iso",
}


def detect_mime_from_magic(data: bytes, fallback_type: str) -> str:
    """Detect MIME type from leading magic bytes buffer."""
    if not data:
        return fallback_type

    for signature, mime_type in MAGIC_SIGNATURES:
        if data.startswith(signature):
            return mime_type

    return fallback_type


def sanitize_attachment_filename(
    filename: str | None, default_name: str = "attachment.bin"
) -> str:
    """Sanitize attachment filename removing path traversal constructs."""
    if not filename:
        return default_name

    decoded = decode_rfc2047_header(filename)
    clean_name = Path(decoded).name
    # Strip null bytes and control chars
    clean_name = "".join(
        c
        for c in clean_name
        if c.isprintable() and c not in ("/", "\\", ":", "*", "?", '"', "<", ">", "|")
    )
    return clean_name or default_name


def extract_attachment_dto(part: Message) -> ExtractedAttachmentDTO | None:
    """Extract ExtractedAttachmentDTO from raw email MIME Message part."""
    payload = part.get_payload(decode=True)
    if not isinstance(payload, bytes):
        return None

    raw_filename = part.get_filename()
    filename = sanitize_attachment_filename(raw_filename)
    declared_content_type = part.get_content_type().lower()
    detected_mime_type = detect_mime_from_magic(payload, declared_content_type)

    size_bytes = len(payload)
    sha256_hash = hashlib.sha256(payload).hexdigest()
    md5_hash = hashlib.md5(payload).hexdigest()

    content_id = str(part.get("Content-ID", "")).strip("<> ") or None
    disposition = str(part.get("Content-Disposition", "")).lower()
    is_inline = "inline" in disposition or (
        content_id is not None and "image/" in detected_mime_type
    )

    return ExtractedAttachmentDTO(
        filename=filename,
        declared_content_type=declared_content_type,
        detected_mime_type=detected_mime_type,
        size_bytes=size_bytes,
        sha256=sha256_hash,
        md5=md5_hash,
        content_id=content_id,
        is_inline=is_inline,
        raw_data=payload,
    )
