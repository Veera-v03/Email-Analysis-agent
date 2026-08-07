"""Unicode normalization, zero-width character stripping, and homoglyph detection."""

from __future__ import annotations

import re
import unicodedata

# Zero-width spaces and invisible control characters: \u200B, \u200C, \u200D, \uFEFF, \u202E (RTO)
ZERO_WIDTH_CHARS = re.compile(r"[\u200B\u200C\u200D\uFEFF\u202E]")


def detect_zero_width_chars(text: str) -> bool:
    """Return True if text contains hidden zero-width or control override characters."""
    if not text:
        return False
    return bool(ZERO_WIDTH_CHARS.search(text))


def strip_zero_width_chars(text: str) -> str:
    """Strip zero-width spaces and control characters from text."""
    if not text:
        return ""
    return ZERO_WIDTH_CHARS.sub("", text)


def normalize_unicode_nfkc(text: str) -> str:
    """Apply NFKC Unicode normalization to standard canonical representation."""
    if not text:
        return ""
    cleaned = strip_zero_width_chars(text)
    return unicodedata.normalize("NFKC", cleaned)


def detect_homoglyphs(text: str) -> bool:
    """Detect presence of mixed script homoglyphs (e.g. Cyrillic 'а' in Latin text)."""
    if not text:
        return False

    scripts = set()
    for ch in text:
        if ch.isalpha():
            name = unicodedata.name(ch, "")
            if "CYRILLIC" in name:
                scripts.add("CYRILLIC")
            elif "LATIN" in name:
                scripts.add("LATIN")
            elif "GREEK" in name:
                scripts.add("GREEK")

    return len(scripts) > 1
