"""Body parsing subpackage for ScamON Enterprise."""

from __future__ import annotations

from src.parsing.body.charset_detector import decode_bytes_to_utf8
from src.parsing.body.html_normalizer import extract_text_from_html, sanitize_html_body
from src.parsing.body.mime_tree_walker import MimePartContent, walk_mime_tree
from src.parsing.body.unicode_cleaner import (
    detect_homoglyphs,
    detect_zero_width_chars,
    normalize_unicode_nfkc,
    strip_zero_width_chars,
)

__all__ = [
    "MimePartContent",
    "decode_bytes_to_utf8",
    "detect_homoglyphs",
    "detect_zero_width_chars",
    "extract_text_from_html",
    "normalize_unicode_nfkc",
    "sanitize_html_body",
    "strip_zero_width_chars",
    "walk_mime_tree",
]
