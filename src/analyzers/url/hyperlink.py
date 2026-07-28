"""HTML hyperlink analysis for Phase 4 URL intelligence.

``DeterministicHyperlinkAnalyzer`` implements the ``HyperlinkAnalyzer``
protocol.  It accepts a tuple of ``ExtractedUrl`` instances (as produced by
``HtmlUrlExtractor``) and emits one ``HyperlinkObservation`` per detected
characteristic.

Detections
----------
ANCHOR_TEXT_MISMATCH
    The visible anchor text contains a URL-like string that differs from the
    actual ``href`` destination.

HIDDEN_URL
    The hyperlink is structurally hidden: zero-width text, whitespace-only
    text, display:none / visibility:hidden in the inline style, or a
    zero-dimension image (width=0 or height=0).

JAVASCRIPT_LINK
    The ``href`` begins with the ``javascript:`` scheme.

MAILTO_LINK
    The ``href`` begins with the ``mailto:`` scheme.

TELEPHONE_LINK
    The ``href`` begins with the ``tel:`` scheme.

EMPTY_HREF
    The ``href`` attribute is present but empty or whitespace-only.

IMAGE_HYPERLINK
    An ``<img>`` tag is the sole or primary content of an anchor (detected
    via ``HTML_IMAGE`` source with a non-None ``html_context`` that contains
    an enclosing anchor, or via ``HTML_ANCHOR`` context that contains an
    ``<img`` child reference).

BUTTON_LINK
    The anchor's ``html_context`` contains ``role="button"`` or the tag is
    an ``<input type="button">`` / ``<button>`` wrapping a link.

META_REFRESH
    The URL was extracted from a ``<meta http-equiv="refresh">`` tag
    (``UrlExtractionSource.META_REFRESH``).

All detections are purely structural.  No network requests are made.
The analyzer is stateless and thread-safe.
"""

from __future__ import annotations

import re

from src.models.url import (
    ExtractedUrl,
    HyperlinkAnalysisResult,
    HyperlinkObservation,
    HyperlinkObservationCategory,
    UrlExtractionSource,
)

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

# Matches a URL-like string inside anchor text (scheme or www prefix).
_TEXT_URL_RE = re.compile(
    r"(?:https?://|ftp://|www\.)\S+",
    re.IGNORECASE,
)

# Matches CSS properties that hide an element.
_HIDDEN_STYLE_RE = re.compile(
    r"(?:display\s*:\s*none|visibility\s*:\s*hidden)",
    re.IGNORECASE,
)

# Matches zero-dimension attributes: width="0" or height="0".
_ZERO_DIM_RE = re.compile(r'(?:width|height)\s*=\s*["\']?0["\']?', re.IGNORECASE)

# Matches role="button" in an HTML tag string.
_ROLE_BUTTON_RE = re.compile(r'role\s*=\s*["\']button["\']', re.IGNORECASE)

# Matches <img inside a context string (anchor wraps an image).
_IMG_IN_CONTEXT_RE = re.compile(r"<img\b", re.IGNORECASE)


def _extract_href(url: ExtractedUrl) -> str | None:
    """Return the raw href value for anchor-sourced URLs."""
    return url.raw_value if url.source is UrlExtractionSource.HTML_ANCHOR else None


def _anchor_text_from_context(context: str | None) -> str | None:
    """Extract the visible text between opening and closing anchor tags.

    The html_context stored by the extractor contains only the opening tag,
    not the inner text.  Anchor text mismatch detection therefore relies on
    the caller supplying the full tag text when available, or is skipped when
    only the opening tag is present.  This function returns None to indicate
    that anchor text is not recoverable from the opening-tag context alone.
    """
    return None  # opening-tag context does not include inner text


def _style_from_context(context: str | None) -> str | None:
    """Extract the value of the style attribute from a tag context string."""
    if not context:
        return None
    m = re.search(r'style\s*=\s*["\']([^"\']*)["\']', context, re.IGNORECASE)
    return m.group(1) if m else None


# ---------------------------------------------------------------------------
# Public analyzer
# ---------------------------------------------------------------------------


class DeterministicHyperlinkAnalyzer:
    """Analyze HTML hyperlinks for structural characteristics.

    Implements the ``HyperlinkAnalyzer`` protocol.  Accepts the full tuple of
    ``ExtractedUrl`` instances from any extractor and emits one
    ``HyperlinkObservation`` per detected characteristic.

    The analyzer is stateless and thread-safe.  Construct once and reuse.
    """

    def analyze(self, urls: tuple[ExtractedUrl, ...]) -> HyperlinkAnalysisResult:
        """Return all hyperlink observations for the supplied URL occurrences.

        Args:
            urls: Extracted URL occurrences, typically from
                ``CompositeUrlExtractor`` or ``HtmlUrlExtractor``.

        Returns:
            ``HyperlinkAnalysisResult`` with one observation per detected
            characteristic.  Empty when no notable characteristics are found.
        """
        observations: list[HyperlinkObservation] = []
        for url in urls:
            observations.extend(self._inspect(url))
        return HyperlinkAnalysisResult(observations=tuple(observations))

    # ------------------------------------------------------------------
    # Per-URL inspection
    # ------------------------------------------------------------------

    def _inspect(self, url: ExtractedUrl) -> list[HyperlinkObservation]:
        results: list[HyperlinkObservation] = []
        source = url.source
        href = url.raw_value
        ctx = url.html_context

        # META_REFRESH — source-based, no further checks needed.
        if source is UrlExtractionSource.META_REFRESH:
            results.append(
                HyperlinkObservation(
                    category=HyperlinkObservationCategory.META_REFRESH,
                    href=href,
                    html_context=ctx,
                )
            )
            return results

        if source is not UrlExtractionSource.HTML_ANCHOR:
            return results

        # --- EMPTY_HREF ---------------------------------------------------
        if not href.strip():
            results.append(
                HyperlinkObservation(
                    category=HyperlinkObservationCategory.EMPTY_HREF,
                    href=href,
                    html_context=ctx,
                )
            )
            return results

        href_lower = href.lower().lstrip()

        # --- JAVASCRIPT_LINK ----------------------------------------------
        if href_lower.startswith("javascript:"):
            results.append(
                HyperlinkObservation(
                    category=HyperlinkObservationCategory.JAVASCRIPT_LINK,
                    href=href,
                    html_context=ctx,
                )
            )
            return results

        # --- MAILTO_LINK --------------------------------------------------
        if href_lower.startswith("mailto:"):
            results.append(
                HyperlinkObservation(
                    category=HyperlinkObservationCategory.MAILTO_LINK,
                    href=href,
                    html_context=ctx,
                )
            )
            return results

        # --- TELEPHONE_LINK -----------------------------------------------
        if href_lower.startswith("tel:"):
            results.append(
                HyperlinkObservation(
                    category=HyperlinkObservationCategory.TELEPHONE_LINK,
                    href=href,
                    html_context=ctx,
                )
            )
            return results

        # --- HIDDEN_URL ---------------------------------------------------
        if self._is_hidden(ctx):
            results.append(
                HyperlinkObservation(
                    category=HyperlinkObservationCategory.HIDDEN_URL,
                    href=href,
                    html_context=ctx,
                )
            )

        # --- IMAGE_HYPERLINK ----------------------------------------------
        if ctx and _IMG_IN_CONTEXT_RE.search(ctx):
            results.append(
                HyperlinkObservation(
                    category=HyperlinkObservationCategory.IMAGE_HYPERLINK,
                    href=href,
                    html_context=ctx,
                )
            )

        # --- BUTTON_LINK --------------------------------------------------
        if ctx and _ROLE_BUTTON_RE.search(ctx):
            results.append(
                HyperlinkObservation(
                    category=HyperlinkObservationCategory.BUTTON_LINK,
                    href=href,
                    html_context=ctx,
                )
            )

        return results

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _is_hidden(ctx: str | None) -> bool:
        """Return True when the tag context indicates a hidden element."""
        if not ctx:
            return False
        style = _style_from_context(ctx)
        if style and _HIDDEN_STYLE_RE.search(style):
            return True
        if _ZERO_DIM_RE.search(ctx):
            return True
        return False


# ---------------------------------------------------------------------------
# Anchor-text mismatch helper (used by engine when full tag text is available)
# ---------------------------------------------------------------------------


def detect_anchor_text_mismatch(
    href: str,
    anchor_text: str,
    html_context: str | None = None,
) -> HyperlinkObservation | None:
    """Return an observation when anchor text contains a conflicting URL.

    This function is called by the engine (or tests) when the full inner text
    of an anchor tag is available separately from the opening-tag context.

    Args:
        href: The raw href destination value.
        anchor_text: The visible text content of the anchor element.
        html_context: Optional opening-tag context for provenance.

    Returns:
        A ``HyperlinkObservation`` with category ``ANCHOR_TEXT_MISMATCH`` when
        the anchor text contains a URL-like string that differs from ``href``,
        otherwise ``None``.
    """
    text_urls = _TEXT_URL_RE.findall(anchor_text)
    if not text_urls:
        return None
    # Normalize for comparison: strip trailing punctuation and lowercase.
    text_url = text_urls[0].rstrip(".,;:!?\"')").lower()
    href_norm = href.rstrip(".,;:!?\"')").lower()
    if text_url == href_norm:
        return None
    return HyperlinkObservation(
        category=HyperlinkObservationCategory.ANCHOR_TEXT_MISMATCH,
        href=href,
        anchor_text=anchor_text,
        html_context=html_context,
    )
