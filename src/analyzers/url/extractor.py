"""URL extraction from email message fields.

Three extractors are provided:

- ``RegexUrlExtractor`` — scans plain-text fields (``body_text``, ``subject``)
  using a regex.  Unchanged from Milestone 4.1 baseline.
- ``HtmlUrlExtractor`` — parses HTML embedded in ``body_text`` using the
  stdlib ``html.parser`` and extracts URLs from anchor href, image src, form
  action, CSS url(), meta refresh, inline style attributes, SVG references,
  and JavaScript string literals.  No third-party HTML library is required.
- ``CompositeUrlExtractor`` — runs both extractors, deduplicates by
  (raw_value, source) while preserving first-seen order, and returns a single
  ordered tuple.

None of these classes perform normalization, parsing, or analysis.
"""

from __future__ import annotations

import re
from html.parser import HTMLParser

from src.models.email import EmailInput
from src.models.url import (
    MAX_EXTRACTION_CONTEXT_LENGTH,
    MAX_RAW_URL_LENGTH,
    ExtractedUrl,
    UrlExtractionSource,
)

# ---------------------------------------------------------------------------
# Shared URL body pattern
# ---------------------------------------------------------------------------

_SCHEME_PATTERN = r"(?:https?|ftp|mailto|data|javascript)://"
_WWW_PATTERN = r"www\."
_URL_BODY_CHARS = r"[^\s\"<>\[\]{}|\\^`\x00-\x1f\x7f]"
_URL_BODY = _URL_BODY_CHARS + r"+"

_URL_RE = re.compile(
    r"(?:" + _SCHEME_PATTERN + r"|" + _WWW_PATTERN + r")" + _URL_BODY,
    re.IGNORECASE | re.UNICODE,
)

# Characters stripped from the right end of a plain-text regex match.
# Forward slash is intentionally excluded so path-terminating slashes survive.
_TRAILING_PUNCTUATION = frozenset(".,;:!?\"')")

_MAX_URLS_PER_SOURCE = 512


def _strip_trailing(value: str) -> str:
    """Remove trailing prose punctuation from a URL match."""
    while value and value[-1] in _TRAILING_PUNCTUATION:
        value = value[:-1]
    return value


# CSS url(...) — captures the inner value with optional quotes.
_CSS_URL_RE = re.compile(
    r"""url\(\s*['"]?([^'"\)\s]+)['"]?\s*\)""",
    re.IGNORECASE,
)

# JavaScript string literals — single or double quoted, containing a URL.
_JS_STRING_RE = re.compile(
    r"""(?:["'])((https?|ftp)://[^\s"'<>]+)(?:["'])""",
    re.IGNORECASE,
)


# ---------------------------------------------------------------------------
# Plain-text extractor
# ---------------------------------------------------------------------------


class RegexUrlExtractor:
    """Extract raw URL occurrences from plain-text email fields using regex.

    Scans ``body_text`` and ``subject``.  Each match is returned as an
    ``ExtractedUrl`` preserving exact raw text, source field, and character
    position.  URLs longer than ``MAX_RAW_URL_LENGTH`` are silently discarded.
    Never raises on malformed input.

    Args:
        max_urls_per_source: Maximum URL matches retained per source field.
    """

    def __init__(self, max_urls_per_source: int = _MAX_URLS_PER_SOURCE) -> None:
        self._max = max_urls_per_source

    def extract(self, email: EmailInput) -> tuple[ExtractedUrl, ...]:
        """Extract all URL occurrences from the email's plain-text fields."""
        results: list[ExtractedUrl] = []
        results.extend(self._scan(email.body_text, UrlExtractionSource.BODY_TEXT))
        results.extend(self._scan(email.header.subject, UrlExtractionSource.SUBJECT))
        return tuple(results)

    def _scan(self, text: str, source: UrlExtractionSource) -> list[ExtractedUrl]:
        extracted: list[ExtractedUrl] = []
        for match in _URL_RE.finditer(text):
            if len(extracted) >= self._max:
                break
            raw = _strip_trailing(match.group())
            if not raw or len(raw) > MAX_RAW_URL_LENGTH:
                continue
            extracted.append(
                ExtractedUrl(raw_value=raw, source=source, position=match.start())
            )
        return extracted


# ---------------------------------------------------------------------------
# HTML extractor
# ---------------------------------------------------------------------------


class _UrlHTMLParser(HTMLParser):
    """Collect URLs from HTML attributes and inline content.

    Handles:
    - ``<a href="...">``                → HTML_ANCHOR
    - ``<img src="...">``               → HTML_IMAGE
    - ``<form action="...">``           → HTML_FORM
    - ``<meta http-equiv="refresh" content="...">`` → META_REFRESH
    - ``style="... url(...) ..."``      → INLINE_STYLE (any tag)
    - ``<link href="...">``             → CSS_URL
    - ``<svg:image href/xlink:href>``   → SVG_REFERENCE
    - ``<use href/xlink:href>``         → SVG_REFERENCE
    - ``<script>`` body text            → JS_STRING
    """

    def __init__(self, html: str) -> None:
        super().__init__(convert_charrefs=True)
        self._html = html
        self.found: list[tuple[str, UrlExtractionSource, int, str | None]] = []
        self._in_script = False

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _add(
        self,
        raw: str,
        source: UrlExtractionSource,
        position: int,
        context: str | None,
    ) -> None:
        raw = raw.strip()
        if not raw or len(raw) > MAX_RAW_URL_LENGTH:
            return
        ctx = context[:MAX_EXTRACTION_CONTEXT_LENGTH] if context else None
        self.found.append((raw, source, position, ctx))

    def _tag_context(self, tag: str, attrs: list[tuple[str, str | None]]) -> str:
        """Reconstruct a compact tag string for html_context."""
        parts = [f"<{tag}"]
        for name, value in attrs:
            if value is not None:
                parts.append(f' {name}="{value}"')
            else:
                parts.append(f" {name}")
        return "".join(parts) + ">"

    def _attr(self, attrs: list[tuple[str, str | None]], name: str) -> str | None:
        for k, v in attrs:
            if k == name:
                return v
        return None

    # ------------------------------------------------------------------
    # HTMLParser callbacks
    # ------------------------------------------------------------------

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        tag_lower = tag.lower()
        context = self._tag_context(tag, attrs)
        pos = self.getpos()
        # Approximate byte offset: line * avg_line_length is unreliable;
        # use 0 as position for HTML-sourced URLs (position within body_text
        # is not meaningful for structured HTML attributes).
        _ = pos  # position tracking deferred to composite layer

        if tag_lower == "a":
            href = self._attr(attrs, "href")
            if href is not None:
                self._add(href, UrlExtractionSource.HTML_ANCHOR, 0, context)

        elif tag_lower == "img":
            src = self._attr(attrs, "src")
            if src is not None:
                self._add(src, UrlExtractionSource.HTML_IMAGE, 0, context)
            # srcset may contain multiple URLs
            srcset = self._attr(attrs, "srcset")
            if srcset:
                for part in srcset.split(","):
                    candidate = part.strip().split()[0] if part.strip() else ""
                    if candidate:
                        self._add(
                            candidate,
                            UrlExtractionSource.HTML_IMAGE,
                            0,
                            context,
                        )

        elif tag_lower == "form":
            action = self._attr(attrs, "action")
            if action is not None:
                self._add(action, UrlExtractionSource.HTML_FORM, 0, context)

        elif tag_lower == "meta":
            equiv = self._attr(attrs, "http-equiv") or ""
            if equiv.lower() == "refresh":
                content = self._attr(attrs, "content") or ""
                # content="5; url=https://..."
                url_match = re.search(r"url\s*=\s*['\"]?([^'\";\s]+)", content, re.I)
                if url_match:
                    self._add(
                        url_match.group(1),
                        UrlExtractionSource.META_REFRESH,
                        0,
                        context,
                    )

        elif tag_lower == "link":
            href = self._attr(attrs, "href")
            if href is not None:
                self._add(href, UrlExtractionSource.CSS_URL, 0, context)

        elif tag_lower in ("image", "svg:image"):
            for attr_name in ("href", "xlink:href"):
                val = self._attr(attrs, attr_name)
                if val is not None:
                    self._add(val, UrlExtractionSource.SVG_REFERENCE, 0, context)

        elif tag_lower == "use":
            for attr_name in ("href", "xlink:href"):
                val = self._attr(attrs, attr_name)
                if val is not None:
                    self._add(val, UrlExtractionSource.SVG_REFERENCE, 0, context)

        elif tag_lower == "script":
            self._in_script = True

        # Inline style on any tag
        style = self._attr(attrs, "style")
        if style:
            for m in _CSS_URL_RE.finditer(style):
                self._add(m.group(1), UrlExtractionSource.INLINE_STYLE, 0, context)

    def handle_endtag(self, tag: str) -> None:
        if tag.lower() == "script":
            self._in_script = False

    def handle_data(self, data: str) -> None:
        if self._in_script:
            for m in _JS_STRING_RE.finditer(data):
                self._add(m.group(1), UrlExtractionSource.JS_STRING, 0, None)


class HtmlUrlExtractor:
    """Extract URLs from HTML embedded in ``body_text``.

    Uses the stdlib ``html.parser`` — no third-party dependencies.
    Extracts from: anchor href, image src/srcset, form action, meta refresh,
    inline style attributes, link href (CSS), SVG image/use references, and
    JavaScript string literals inside ``<script>`` blocks.

    Only ``body_text`` is scanned; HTML is not expected in ``subject``.
    Never raises on malformed HTML.
    """

    def extract(self, email: EmailInput) -> tuple[ExtractedUrl, ...]:
        """Extract HTML-sourced URL occurrences from ``body_text``."""
        parser = _UrlHTMLParser(email.body_text)
        try:
            parser.feed(email.body_text)
        except Exception:  # noqa: BLE001
            return ()

        results: list[ExtractedUrl] = []
        for raw, source, position, context in parser.found:
            if len(raw) > MAX_RAW_URL_LENGTH:
                continue
            results.append(
                ExtractedUrl(
                    raw_value=raw,
                    source=source,
                    position=position,
                    html_context=context,
                )
            )
        return tuple(results)


# ---------------------------------------------------------------------------
# Composite extractor with deduplication
# ---------------------------------------------------------------------------


class CompositeUrlExtractor:
    """Run plain-text and HTML extractors, deduplicate, and preserve order.

    Deduplication key is ``(raw_value, source)``.  The first occurrence of
    each key is kept; subsequent duplicates are dropped.  Plain-text results
    appear before HTML results in the output tuple.

    Args:
        max_urls_per_source: Forwarded to ``RegexUrlExtractor``.
    """

    def __init__(self, max_urls_per_source: int = _MAX_URLS_PER_SOURCE) -> None:
        self._text = RegexUrlExtractor(max_urls_per_source)
        self._html = HtmlUrlExtractor()

    def extract(self, email: EmailInput) -> tuple[ExtractedUrl, ...]:
        """Return deduplicated, ordered URL occurrences from all sources."""
        seen: set[tuple[str, UrlExtractionSource]] = set()
        results: list[ExtractedUrl] = []
        for url in (*self._text.extract(email), *self._html.extract(email)):
            key = (url.raw_value, url.source)
            if key not in seen:
                seen.add(key)
                results.append(url)
        return tuple(results)
