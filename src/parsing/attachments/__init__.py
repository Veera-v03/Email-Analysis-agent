"""Attachments parsing subpackage for ScamON Enterprise."""

from __future__ import annotations

from src.parsing.attachments.cid_mapper import separate_attachments_and_inline_images
from src.parsing.attachments.extractor import (
    DANGEROUS_EXTENSIONS,
    detect_mime_from_magic,
    extract_attachment_dto,
    sanitize_attachment_filename,
)

__all__ = [
    "DANGEROUS_EXTENSIONS",
    "detect_mime_from_magic",
    "extract_attachment_dto",
    "sanitize_attachment_filename",
    "separate_attachments_and_inline_images",
]
