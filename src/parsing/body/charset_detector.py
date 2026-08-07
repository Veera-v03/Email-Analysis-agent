"""Character encoding detection and fallback normalization."""

from __future__ import annotations

import charset_normalizer


def decode_bytes_to_utf8(data: bytes, declared_charset: str | None = None) -> str:
    """Decode raw bytes payload into UTF-8 string with character set detection fallback."""
    if not data:
        return ""

    # 1. Try declared character set if present
    if declared_charset:
        try:
            return data.decode(declared_charset, errors="replace")
        except (LookupError, UnicodeDecodeError):
            pass

    # 2. Try UTF-8
    try:
        return data.decode("utf-8")
    except UnicodeDecodeError:
        pass

    # 3. Detect character set using charset_normalizer
    try:
        matches = charset_normalizer.from_bytes(data)
        best_match = matches.best()
        if best_match and best_match.encoding:
            return str(best_match)
    except Exception:
        pass

    # 4. Final fallback to ISO-8859-1 / Latin1 with replacement
    return data.decode("latin1", errors="replace")
