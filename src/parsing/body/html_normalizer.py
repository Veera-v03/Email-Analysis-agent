"""HTML DOM sanitization, rendering text extraction, and HTML normalization."""

from __future__ import annotations

import re
from html.parser import HTMLParser as StdHTMLParser

from src.parsing.body.unicode_cleaner import normalize_unicode_nfkc


class _HTMLTextExtractor(StdHTMLParser):
    def __init__(self) -> None:
        super().__init__()
        self.result: list[str] = []
        self.ignore: bool = False

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        if tag.lower() in ("script", "style", "iframe", "object", "embed"):
            self.ignore = True

    def handle_endtag(self, tag: str) -> None:
        if tag.lower() in ("script", "style", "iframe", "object", "embed"):
            self.ignore = False

    def handle_data(self, data: str) -> None:
        if not self.ignore and data.strip():
            self.result.append(data.strip())


def extract_text_from_html(html_content: str) -> str:
    """Extract rendered plain text from HTML string."""
    if not html_content or not html_content.strip():
        return ""

    try:
        extractor = _HTMLTextExtractor()
        extractor.feed(html_content)
        raw_text = " ".join(extractor.result)
        return normalize_unicode_nfkc(raw_text)
    except Exception:
        clean = re.sub(r"<[^>]+>", " ", html_content)
        return normalize_unicode_nfkc(clean)


def sanitize_html_body(html_content: str) -> str:
    """Sanitize HTML body removing script tags and active elements."""
    if not html_content:
        return ""

    cleaned = re.sub(
        r"<(script|style|object|embed|iframe)[^>]*>.*?</\1>",
        "",
        html_content,
        flags=re.IGNORECASE | re.DOTALL,
    )
    return cleaned
