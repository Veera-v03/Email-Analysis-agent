"""HTML DOM sanitization, rendering text extraction, HTML normalization, and DOM signal extraction."""

from __future__ import annotations

import re
from html.parser import HTMLParser as StdHTMLParser
from typing import Any

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


def extract_dom_signals(html_content: str) -> dict[str, Any]:
    """Extract structural DOM anomaly signals from HTML content.

    Surfaces:
    - hidden text CSS rules (display:none, visibility:hidden, font-size:0px, color:transparent)
    - form action URLs (<form action="...">)
    - HTML entity obfuscation counts (&#x...)
    - script tag counts (<script>)
    """
    if not html_content or not html_content.strip():
        return {
            "has_hidden_text": False,
            "hidden_text_snippets": [],
            "external_form_actions": [],
            "script_tag_count": 0,
            "html_entity_obfuscation_count": 0,
        }

    hidden_snippets: list[str] = []

    # 1. Hidden Text Detection via CSS inline styles
    hidden_style_patterns = [
        r'style="[^"]*display:\s*none[^"]*"[^>]*>(?P<text>[^<]+)</',
        r'style="[^"]*visibility:\s*hidden[^"]*"[^>]*>(?P<text>[^<]+)</',
        r'style="[^"]*font-size:\s*0(?:px|pt)?[^"]*"[^>]*>(?P<text>[^<]+)</',
        r'style="[^"]*color:\s*transparent[^"]*"[^>]*>(?P<text>[^<]+)</',
    ]

    for pat in hidden_style_patterns:
        for match in re.finditer(pat, html_content, flags=re.IGNORECASE):
            text = match.group("text").strip()
            if text:
                hidden_snippets.append(text)

    # 2. Form Action URLs
    form_actions: list[str] = []
    form_matches = re.findall(
        r'<form[^>]+action=["\'](?P<action>[^"\']+)["\']',
        html_content,
        flags=re.IGNORECASE,
    )
    for action in form_matches:
        if action and not action.startswith("#"):
            form_actions.append(action)

    # 3. Script Tag Count
    script_count = len(re.findall(r"<script[^>]*>", html_content, flags=re.IGNORECASE))

    # 4. Hex Entity Obfuscation Count
    hex_obfuscations = len(re.findall(r"&#x[0-9a-fA-F]+;", html_content))

    return {
        "has_hidden_text": len(hidden_snippets) > 0,
        "hidden_text_snippets": hidden_snippets,
        "external_form_actions": form_actions,
        "script_tag_count": script_count,
        "html_entity_obfuscation_count": hex_obfuscations,
    }
