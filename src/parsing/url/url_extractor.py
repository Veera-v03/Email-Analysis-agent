"""URL extraction from HTML DOM and plaintext with link text mismatch detection."""

from __future__ import annotations

import re
from html.parser import HTMLParser as StdHTMLParser
from urllib.parse import urlparse

from src.parsing.models import ExtractedURLDTO

# Regex pattern for bare URLs in plain text
URL_REGEX = re.compile(
    r"https?://(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}(?::\d+)?(?:/[^\s<>'\"\)]*)?",
    re.IGNORECASE,
)

KNOWN_SHORTENERS = {
    "bit.ly",
    "tinyurl.com",
    "t.co",
    "goo.gl",
    "ow.ly",
    "is.gd",
    "buff.ly",
    "adf.ly",
}


class _HTMLAnchorExtractor(StdHTMLParser):
    def __init__(self) -> None:
        super().__init__()
        self.links: list[tuple[str, str]] = []
        self.current_href: str | None = None
        self.current_text: list[str] = []

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        if tag.lower() == "a":
            for attr_name, attr_val in attrs:
                if attr_name.lower() == "href" and attr_val:
                    self.current_href = attr_val
                    self.current_text = []

    def handle_endtag(self, tag: str) -> None:
        if tag.lower() == "a" and self.current_href:
            anchor_text = " ".join(self.current_text).strip()
            self.links.append((self.current_href, anchor_text))
            self.current_href = None
            self.current_text = []

    def handle_data(self, data: str) -> None:
        if self.current_href and data.strip():
            self.current_text.append(data.strip())


def parse_url_entity(
    target_url: str, anchor_text: str | None = None
) -> ExtractedURLDTO | None:
    """Construct ExtractedURLDTO analyzing target URL and display anchor text."""
    if not target_url or not target_url.strip():
        return None

    cleaned_url = target_url.strip()
    try:
        parsed = urlparse(cleaned_url)
        scheme = parsed.scheme.lower() or "http"
        domain = parsed.netloc.lower()

        if not domain:
            return None

        # Check if domain is a known shortener
        is_shortened = any(
            domain == short or domain.endswith("." + short)
            for short in KNOWN_SHORTENERS
        )

        # Check for link display mismatch (e.g. anchor text is a different URL/domain)
        is_mismatched = False
        if anchor_text:
            cleaned_anchor = anchor_text.strip()
            anchor_match = URL_REGEX.search(cleaned_anchor)
            if anchor_match:
                displayed_url = anchor_match.group(0)
                disp_domain = urlparse(displayed_url).netloc.lower()
                if disp_domain and disp_domain != domain:
                    is_mismatched = True

        return ExtractedURLDTO(
            url=cleaned_url,
            scheme=scheme,
            domain=domain,
            anchor_text=anchor_text.strip() if anchor_text else None,
            is_mismatched=is_mismatched,
            is_shortened=is_shortened,
        )
    except Exception:
        return None


def extract_urls_from_html(html_content: str) -> list[ExtractedURLDTO]:
    """Extract ExtractedURLDTO objects from HTML <a> tags."""
    urls: list[ExtractedURLDTO] = []
    if not html_content:
        return urls

    try:
        extractor = _HTMLAnchorExtractor()
        extractor.feed(html_content)
        for href, anchor_text in extractor.links:
            if href.startswith("http://") or href.startswith("https://"):
                dto = parse_url_entity(href, anchor_text=anchor_text)
                if dto:
                    urls.append(dto)
    except Exception:
        pass

    return urls


def extract_urls_from_text(text: str) -> list[ExtractedURLDTO]:
    """Extract ExtractedURLDTO objects from plain text using regex."""
    urls: list[ExtractedURLDTO] = []
    if not text:
        return urls

    matches = URL_REGEX.findall(text)
    for match_url in matches:
        dto = parse_url_entity(match_url)
        if dto:
            urls.append(dto)

    return urls
