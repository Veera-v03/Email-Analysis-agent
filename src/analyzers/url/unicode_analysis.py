"""Deterministic Unicode analysis for Phase 4 URL intelligence.

``DeterministicUrlUnicodeAnalyzer`` implements the ``UrlUnicodeAnalyzer``
protocol.  It accepts ``ParsedUrlComponents`` and returns a fully populated
``UrlUnicodeAnalysis`` with evidence for five detection types:

Punycode detection
    Any ``xn--`` ACE label in the host sets ``contains_punycode``.

Mixed-script detection
    Unicode script categories are identified for every non-ASCII character
    in the host.  When two or more distinct scripts are present,
    ``has_mixed_scripts`` is True and ``detected_scripts`` lists them.

Homograph / confusable-character detection
    Every non-ASCII character in the host is looked up in a curated table of
    characters that are visually similar to ASCII letters or digits.  Matches
    are recorded in ``confusable_characters`` as (original, lookalike) pairs.

Unicode normalization form
    The host is tested against NFC, NFKC, NFD, and NFKD.  The first form
    under which the host is already normalized is recorded in
    ``normalization_form``.  ASCII-only hosts record ``NONE``.

Percent-encoded Unicode
    Any ``%XX`` sequence in the path or query that decodes to a non-ASCII
    code point sets ``contains_percent_encoded_unicode``.

RTL character detection
    Any character whose Unicode bidirectional category is R, AL, or RLE sets
    ``has_rtl_characters``.

All analysis is purely structural.  No DNS resolution, no HTTP requests,
no external lookups.  The analyzer is stateless and thread-safe.
"""

from __future__ import annotations

import re
import unicodedata
from typing import Literal
from urllib.parse import unquote

from src.models.url import (
    ParsedUrlComponents,
    UnicodeScriptCategory,
    UrlUnicodeAnalysis,
)

# ---------------------------------------------------------------------------
# Punycode
# ---------------------------------------------------------------------------

_ACE_PREFIX = "xn--"


def _has_punycode(host: str) -> bool:
    return any(label.lower().startswith(_ACE_PREFIX) for label in host.split("."))


# ---------------------------------------------------------------------------
# Script classification
# ---------------------------------------------------------------------------
# Unicode block ranges mapped to UnicodeScriptCategory.
# Ranges are (start, end, category) inclusive.  Checked in order; first match
# wins.  Latin covers Basic Latin + Latin Extended blocks.

_SCRIPT_RANGES: list[tuple[int, int, UnicodeScriptCategory]] = [
    (0x0041, 0x007A, UnicodeScriptCategory.LATIN),  # Basic Latin A-Z a-z
    (0x00C0, 0x024F, UnicodeScriptCategory.LATIN),  # Latin Extended
    (0x0250, 0x02AF, UnicodeScriptCategory.LATIN),  # IPA Extensions (Latin)
    (0x1E00, 0x1EFF, UnicodeScriptCategory.LATIN),  # Latin Extended Additional
    (0x0400, 0x04FF, UnicodeScriptCategory.CYRILLIC),
    (0x0500, 0x052F, UnicodeScriptCategory.CYRILLIC),
    (0x0370, 0x03FF, UnicodeScriptCategory.GREEK),
    (0x1F00, 0x1FFF, UnicodeScriptCategory.GREEK),  # Greek Extended
    (0x0600, 0x06FF, UnicodeScriptCategory.ARABIC),
    (0x0750, 0x077F, UnicodeScriptCategory.ARABIC),
    (0x4E00, 0x9FFF, UnicodeScriptCategory.CJK),
    (0x3400, 0x4DBF, UnicodeScriptCategory.CJK),
    (0x20000, 0x2A6DF, UnicodeScriptCategory.CJK),
    (0x0900, 0x097F, UnicodeScriptCategory.DEVANAGARI),
]


def _script_of(char: str) -> UnicodeScriptCategory | None:
    """Return the script category for a single character.

    ASCII letters are treated as Latin so hosts that mix ASCII Latin text with
    non-ASCII script letters are correctly recognized as mixed-script.
    """
    cp = ord(char)
    if cp < 0x80:
        if "A" <= char <= "Z" or "a" <= char <= "z":
            return UnicodeScriptCategory.LATIN
        return None
    for start, end, category in _SCRIPT_RANGES:
        if start <= cp <= end:
            return category
    return UnicodeScriptCategory.OTHER


def _detect_scripts(text: str) -> tuple[UnicodeScriptCategory, ...]:
    """Return ordered unique script categories found in *text*."""
    seen: list[UnicodeScriptCategory] = []
    for ch in text:
        cat = _script_of(ch)
        if cat is not None and cat not in seen:
            seen.append(cat)
    return tuple(seen)


# ---------------------------------------------------------------------------
# RTL detection
# ---------------------------------------------------------------------------
# Bidirectional categories that indicate right-to-left text.
_RTL_BIDI = frozenset(("R", "AL", "RLE", "RLO", "RLI"))


def _has_rtl(text: str) -> bool:
    return any(unicodedata.bidirectional(ch) in _RTL_BIDI for ch in text)


# ---------------------------------------------------------------------------
# Confusable characters
# ---------------------------------------------------------------------------
# Curated table of non-ASCII characters that are visually similar to ASCII
# letters or digits.  Each entry is (non_ascii_char, ascii_lookalike).
# Sources: Unicode confusables.txt (selected high-impact entries) and
# common IDN homograph attack characters.

_CONFUSABLES: dict[str, str] = {
    # Cyrillic lookalikes
    "\u0430": "a",  # а → a
    "\u0435": "e",  # е → e
    "\u043e": "o",  # о → o
    "\u0440": "r",  # р → r
    "\u0441": "c",  # с → c
    "\u0445": "x",  # х → x
    "\u0443": "y",  # у → y
    "\u0456": "i",  # і → i
    "\u0458": "j",  # ј → j
    "\u0455": "s",  # ѕ → s
    "\u0501": "d",  # ԁ → d
    "\u0503": "g",  # ԃ → g  (approximate)
    # Greek lookalikes
    "\u03bf": "o",  # ο → o  (Greek omicron)
    "\u03b1": "a",  # α → a
    "\u03b5": "e",  # ε → e  (approximate)
    "\u03c1": "p",  # ρ → p  (approximate)
    "\u03bd": "v",  # ν → v  (approximate)
    "\u03c5": "u",  # υ → u  (approximate)
    # Latin Extended lookalikes
    "\u00e0": "a",  # à → a
    "\u00e1": "a",  # á → a
    "\u00e2": "a",  # â → a
    "\u00e4": "a",  # ä → a
    "\u00e5": "a",  # å → a
    "\u00e8": "e",  # è → e
    "\u00e9": "e",  # é → e
    "\u00ea": "e",  # ê → e
    "\u00eb": "e",  # ë → e
    "\u00ec": "i",  # ì → i
    "\u00ed": "i",  # í → i
    "\u00ee": "i",  # î → i
    "\u00ef": "i",  # ï → i
    "\u00f2": "o",  # ò → o
    "\u00f3": "o",  # ó → o
    "\u00f4": "o",  # ô → o
    "\u00f6": "o",  # ö → o
    "\u00f9": "u",  # ù → u
    "\u00fa": "u",  # ú → u
    "\u00fb": "u",  # û → u
    "\u00fc": "u",  # ü → u
    "\u00fd": "y",  # ý → y
    "\u00ff": "y",  # ÿ → y
    "\u00f1": "n",  # ñ → n
    "\u00e7": "c",  # ç → c
    # Fullwidth ASCII
    "\uff41": "a",  # ａ → a
    "\uff42": "b",  # ｂ → b
    "\uff43": "c",  # ｃ → c
    "\uff44": "d",  # ｄ → d
    "\uff45": "e",  # ｅ → e
    "\uff46": "f",  # ｆ → f
    "\uff47": "g",  # ｇ → g
    "\uff48": "h",  # ｈ → h
    "\uff49": "i",  # ｉ → i
    "\uff4a": "j",  # ｊ → j
    "\uff4b": "k",  # ｋ → k
    "\uff4c": "l",  # ｌ → l
    "\uff4d": "m",  # ｍ → m
    "\uff4e": "n",  # ｎ → n
    "\uff4f": "o",  # ｏ → o
    "\uff50": "p",  # ｐ → p
    "\uff51": "q",  # ｑ → q
    "\uff52": "r",  # ｒ → r
    "\uff53": "s",  # ｓ → s
    "\uff54": "t",  # ｔ → t
    "\uff55": "u",  # ｕ → u
    "\uff56": "v",  # ｖ → v
    "\uff57": "w",  # ｗ → w
    "\uff58": "x",  # ｘ → x
    "\uff59": "y",  # ｙ → y
    "\uff5a": "z",  # ｚ → z
}


def _find_confusables(text: str) -> tuple[tuple[str, str], ...]:
    """Return (original_char, ascii_lookalike) pairs for confusable chars."""
    seen: list[tuple[str, str]] = []
    seen_chars: set[str] = set()
    for ch in text:
        if ch not in seen_chars and ch in _CONFUSABLES:
            seen.append((ch, _CONFUSABLES[ch]))
            seen_chars.add(ch)
    return tuple(seen)


# ---------------------------------------------------------------------------
# Percent-encoded Unicode detection
# ---------------------------------------------------------------------------

_PCT_RE = re.compile(r"(%[0-9A-Fa-f]{2})+")


def _has_percent_encoded_unicode(text: str) -> bool:
    """Return True when any %XX sequence decodes to a non-ASCII code point."""
    for match in _PCT_RE.finditer(text):
        try:
            decoded = unquote(match.group(), encoding="utf-8", errors="strict")
            if any(ord(ch) >= 0x80 for ch in decoded):
                return True
        except (ValueError, UnicodeDecodeError):
            continue
    return False


# ---------------------------------------------------------------------------
# Unicode normalization form detection
# ---------------------------------------------------------------------------

_NORM_FORMS: tuple[Literal["NFC", "NFKC", "NFD", "NFKD"], ...] = (
    "NFC",
    "NFKC",
    "NFD",
    "NFKD",
)


def _normalization_form(text: str) -> str:
    """Return the first normalization form under which *text* is stable.

    Returns ``NONE`` for ASCII-only text or when no standard form matches.
    """
    if text.isascii():
        return "NONE"
    for form in _NORM_FORMS:
        if unicodedata.normalize(form, text) == text:
            return form
    return "NONE"


# ---------------------------------------------------------------------------
# Public analyzer
# ---------------------------------------------------------------------------


class DeterministicUrlUnicodeAnalyzer:
    """Analyze Unicode characteristics of parsed URL components.

    Implements the ``UrlUnicodeAnalyzer`` protocol.  All five detection types
    are computed from the supplied ``ParsedUrlComponents`` without any I/O.

    The analyzer is stateless and thread-safe.  Construct once and reuse.
    """

    def analyze(self, components: ParsedUrlComponents) -> UrlUnicodeAnalysis:
        """Return Unicode-level observations for the supplied URL components.

        Analysis targets the host component for script, confusable, punycode,
        and normalization checks.  The path and query are checked for
        percent-encoded Unicode.  RTL detection covers all components.

        Args:
            components: Parsed URL components, typically from a
                ``UrlComponentParser``.

        Returns:
            Fully populated ``UrlUnicodeAnalysis``.  All boolean flags default
            to False and all tuples default to empty when no evidence is found.
        """
        host = components.host or ""
        path = components.path or ""
        query = components.query or ""
        all_text = host + path + query + (components.scheme or "")

        # --- Punycode -----------------------------------------------------
        has_punycode = _has_punycode(host) if host else False

        # --- Non-ASCII ----------------------------------------------------
        contains_non_ascii = any(ord(ch) >= 0x80 for ch in all_text)

        # --- Script detection (host only) ---------------------------------
        scripts = _detect_scripts(host)
        # Mixed script requires at least two distinct script categories.
        # ASCII Latin letters are treated as Latin so a host like
        # "mаil.example.com" is recognized as mixed-script.
        non_ascii_scripts = [s for s in scripts if s is not None]
        has_mixed = len(non_ascii_scripts) >= 2

        # --- RTL ----------------------------------------------------------
        has_rtl = _has_rtl(all_text)

        # --- Confusable characters (host only) ----------------------------
        confusables = _find_confusables(host)

        # --- Percent-encoded Unicode (path + query) -----------------------
        pct_unicode = _has_percent_encoded_unicode(path + query)

        # --- Normalization form (host only) -------------------------------
        norm_form = _normalization_form(host)

        return UrlUnicodeAnalysis(
            contains_non_ascii=contains_non_ascii,
            contains_punycode=has_punycode,
            contains_percent_encoded_unicode=pct_unicode,
            detected_scripts=scripts,
            has_mixed_scripts=has_mixed,
            has_rtl_characters=has_rtl,
            normalization_form=norm_form,
            confusable_characters=confusables,
        )
