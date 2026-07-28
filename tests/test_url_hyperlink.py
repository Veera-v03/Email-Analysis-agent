"""Unit tests for Phase 4 Milestone 4.4 — HTML Hyperlink Analyzer.

Covers:
- Protocol conformance
- All 9 HyperlinkObservationCategory detections
- detect_anchor_text_mismatch helper
- Model contracts (HyperlinkObservation, HyperlinkAnalysisResult)
- HTML context preservation
- Edge cases and adversarial inputs
"""

from __future__ import annotations

import pytest

from src.analyzers.url.contracts import HyperlinkAnalyzer
from src.analyzers.url.hyperlink import (
    DeterministicHyperlinkAnalyzer,
    detect_anchor_text_mismatch,
)
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


def _anchor(
    href: str,
    context: str | None = None,
    position: int = 0,
) -> ExtractedUrl:
    # Preserve the strict ExtractedUrl contract while still exercising the
    # empty-href detection logic for blank values.
    raw_value = href if href else " "
    return ExtractedUrl(
        raw_value=raw_value,
        source=UrlExtractionSource.HTML_ANCHOR,
        position=position,
        html_context=context,
    )


def _meta_refresh(href: str, context: str | None = None) -> ExtractedUrl:
    return ExtractedUrl(
        raw_value=href,
        source=UrlExtractionSource.META_REFRESH,
        position=0,
        html_context=context,
    )


def _image_url(src: str, context: str | None = None) -> ExtractedUrl:
    return ExtractedUrl(
        raw_value=src,
        source=UrlExtractionSource.HTML_IMAGE,
        position=0,
        html_context=context,
    )


def _analyze(*urls: ExtractedUrl) -> HyperlinkAnalysisResult:
    return DeterministicHyperlinkAnalyzer().analyze(tuple(urls))


def _categories(result: HyperlinkAnalysisResult) -> list[HyperlinkObservationCategory]:
    return [obs.category for obs in result.observations]


# ---------------------------------------------------------------------------
# Protocol conformance
# ---------------------------------------------------------------------------


def test_analyzer_satisfies_hyperlink_analyzer_protocol() -> None:
    assert isinstance(DeterministicHyperlinkAnalyzer(), HyperlinkAnalyzer)


# ---------------------------------------------------------------------------
# Model contracts
# ---------------------------------------------------------------------------


def test_hyperlink_observation_is_frozen() -> None:
    obs = HyperlinkObservation(
        category=HyperlinkObservationCategory.JAVASCRIPT_LINK,
        href="javascript:void(0)",
    )
    with pytest.raises(Exception):
        obs.href = "other"  # type: ignore[misc]


def test_hyperlink_analysis_result_is_frozen() -> None:
    result = HyperlinkAnalysisResult()
    with pytest.raises(Exception):
        result.observations = ()  # type: ignore[misc]


def test_hyperlink_analysis_result_default_is_empty() -> None:
    assert HyperlinkAnalysisResult().observations == ()


def test_hyperlink_observation_optional_fields_default_to_none() -> None:
    obs = HyperlinkObservation(category=HyperlinkObservationCategory.EMPTY_HREF)
    assert obs.href is None
    assert obs.anchor_text is None
    assert obs.html_context is None


def test_analyze_empty_tuple_returns_empty_result() -> None:
    result = DeterministicHyperlinkAnalyzer().analyze(())
    assert result.observations == ()


def test_analyze_returns_hyperlink_analysis_result() -> None:
    result = _analyze(_anchor("https://example.com"))
    assert isinstance(result, HyperlinkAnalysisResult)


# ---------------------------------------------------------------------------
# JAVASCRIPT_LINK
# ---------------------------------------------------------------------------


def test_javascript_scheme_detected() -> None:
    result = _analyze(_anchor("javascript:void(0)"))
    assert HyperlinkObservationCategory.JAVASCRIPT_LINK in _categories(result)


def test_javascript_scheme_uppercase_detected() -> None:
    result = _analyze(_anchor("JAVASCRIPT:alert(1)"))
    assert HyperlinkObservationCategory.JAVASCRIPT_LINK in _categories(result)


def test_javascript_scheme_mixed_case_detected() -> None:
    result = _analyze(_anchor("JavaScript:void(0)"))
    assert HyperlinkObservationCategory.JAVASCRIPT_LINK in _categories(result)


def test_javascript_link_href_preserved() -> None:
    href = "javascript:void(0)"
    result = _analyze(_anchor(href))
    obs = next(
        o
        for o in result.observations
        if o.category is HyperlinkObservationCategory.JAVASCRIPT_LINK
    )
    assert obs.href == href


def test_javascript_link_does_not_also_emit_other_categories() -> None:
    result = _analyze(_anchor("javascript:void(0)"))
    cats = _categories(result)
    assert cats == [HyperlinkObservationCategory.JAVASCRIPT_LINK]


# ---------------------------------------------------------------------------
# MAILTO_LINK
# ---------------------------------------------------------------------------


def test_mailto_scheme_detected() -> None:
    result = _analyze(_anchor("mailto:user@example.com"))
    assert HyperlinkObservationCategory.MAILTO_LINK in _categories(result)


def test_mailto_scheme_uppercase_detected() -> None:
    result = _analyze(_anchor("MAILTO:user@example.com"))
    assert HyperlinkObservationCategory.MAILTO_LINK in _categories(result)


def test_mailto_link_href_preserved() -> None:
    href = "mailto:support@example.com?subject=Help"
    result = _analyze(_anchor(href))
    obs = next(
        o
        for o in result.observations
        if o.category is HyperlinkObservationCategory.MAILTO_LINK
    )
    assert obs.href == href


def test_mailto_link_does_not_also_emit_other_categories() -> None:
    result = _analyze(_anchor("mailto:user@example.com"))
    cats = _categories(result)
    assert cats == [HyperlinkObservationCategory.MAILTO_LINK]


# ---------------------------------------------------------------------------
# TELEPHONE_LINK
# ---------------------------------------------------------------------------


def test_tel_scheme_detected() -> None:
    result = _analyze(_anchor("tel:+15551234567"))
    assert HyperlinkObservationCategory.TELEPHONE_LINK in _categories(result)


def test_tel_scheme_uppercase_detected() -> None:
    result = _analyze(_anchor("TEL:+15551234567"))
    assert HyperlinkObservationCategory.TELEPHONE_LINK in _categories(result)


def test_tel_link_href_preserved() -> None:
    href = "tel:+15551234567"
    result = _analyze(_anchor(href))
    obs = next(
        o
        for o in result.observations
        if o.category is HyperlinkObservationCategory.TELEPHONE_LINK
    )
    assert obs.href == href


def test_tel_link_does_not_also_emit_other_categories() -> None:
    result = _analyze(_anchor("tel:+15551234567"))
    cats = _categories(result)
    assert cats == [HyperlinkObservationCategory.TELEPHONE_LINK]


# ---------------------------------------------------------------------------
# EMPTY_HREF
# ---------------------------------------------------------------------------


def test_empty_href_detected() -> None:
    result = _analyze(_anchor(""))
    assert HyperlinkObservationCategory.EMPTY_HREF in _categories(result)


def test_whitespace_only_href_detected_as_empty() -> None:
    result = _analyze(_anchor("   "))
    assert HyperlinkObservationCategory.EMPTY_HREF in _categories(result)


def test_empty_href_stops_further_detection() -> None:
    # An empty href should not also trigger JAVASCRIPT_LINK etc.
    result = _analyze(_anchor(""))
    cats = _categories(result)
    assert cats == [HyperlinkObservationCategory.EMPTY_HREF]


def test_non_empty_href_does_not_trigger_empty_href() -> None:
    result = _analyze(_anchor("https://example.com"))
    assert HyperlinkObservationCategory.EMPTY_HREF not in _categories(result)


# ---------------------------------------------------------------------------
# META_REFRESH
# ---------------------------------------------------------------------------


def test_meta_refresh_source_detected() -> None:
    result = _analyze(_meta_refresh("https://redirect.example.com"))
    assert HyperlinkObservationCategory.META_REFRESH in _categories(result)


def test_meta_refresh_href_preserved() -> None:
    href = "https://redirect.example.com/landing"
    result = _analyze(_meta_refresh(href))
    obs = next(
        o
        for o in result.observations
        if o.category is HyperlinkObservationCategory.META_REFRESH
    )
    assert obs.href == href


def test_meta_refresh_context_preserved() -> None:
    ctx = '<meta http-equiv="refresh" content="5; url=https://redirect.example.com">'
    result = _analyze(_meta_refresh("https://redirect.example.com", context=ctx))
    obs = next(
        o
        for o in result.observations
        if o.category is HyperlinkObservationCategory.META_REFRESH
    )
    assert obs.html_context == ctx


def test_meta_refresh_emits_only_meta_refresh_category() -> None:
    result = _analyze(_meta_refresh("https://redirect.example.com"))
    cats = _categories(result)
    assert cats == [HyperlinkObservationCategory.META_REFRESH]


def test_non_anchor_non_meta_sources_produce_no_observations() -> None:
    result = _analyze(_image_url("https://cdn.example.com/img.png"))
    assert result.observations == ()


# ---------------------------------------------------------------------------
# HIDDEN_URL — display:none
# ---------------------------------------------------------------------------


def test_display_none_style_detected_as_hidden() -> None:
    ctx = '<a href="https://example.com" style="display:none">'
    result = _analyze(_anchor("https://example.com", context=ctx))
    assert HyperlinkObservationCategory.HIDDEN_URL in _categories(result)


def test_display_none_with_spaces_detected_as_hidden() -> None:
    ctx = '<a href="https://example.com" style="display : none">'
    result = _analyze(_anchor("https://example.com", context=ctx))
    assert HyperlinkObservationCategory.HIDDEN_URL in _categories(result)


def test_visibility_hidden_style_detected_as_hidden() -> None:
    ctx = '<a href="https://example.com" style="visibility:hidden">'
    result = _analyze(_anchor("https://example.com", context=ctx))
    assert HyperlinkObservationCategory.HIDDEN_URL in _categories(result)


def test_visibility_hidden_uppercase_detected() -> None:
    ctx = '<a href="https://example.com" style="VISIBILITY:HIDDEN">'
    result = _analyze(_anchor("https://example.com", context=ctx))
    assert HyperlinkObservationCategory.HIDDEN_URL in _categories(result)


# ---------------------------------------------------------------------------
# HIDDEN_URL — zero dimensions
# ---------------------------------------------------------------------------


def test_width_zero_detected_as_hidden() -> None:
    ctx = '<a href="https://example.com" width="0">'
    result = _analyze(_anchor("https://example.com", context=ctx))
    assert HyperlinkObservationCategory.HIDDEN_URL in _categories(result)


def test_height_zero_detected_as_hidden() -> None:
    ctx = '<a href="https://example.com" height="0">'
    result = _analyze(_anchor("https://example.com", context=ctx))
    assert HyperlinkObservationCategory.HIDDEN_URL in _categories(result)


def test_normal_anchor_without_hiding_not_flagged_as_hidden() -> None:
    ctx = '<a href="https://example.com">'
    result = _analyze(_anchor("https://example.com", context=ctx))
    assert HyperlinkObservationCategory.HIDDEN_URL not in _categories(result)


# ---------------------------------------------------------------------------
# IMAGE_HYPERLINK
# ---------------------------------------------------------------------------


def test_img_tag_in_anchor_context_detected_as_image_hyperlink() -> None:
    ctx = '<a href="https://example.com"><img src="logo.png">'
    result = _analyze(_anchor("https://example.com", context=ctx))
    assert HyperlinkObservationCategory.IMAGE_HYPERLINK in _categories(result)


def test_img_tag_uppercase_in_context_detected() -> None:
    ctx = '<a href="https://example.com"><IMG src="logo.png">'
    result = _analyze(_anchor("https://example.com", context=ctx))
    assert HyperlinkObservationCategory.IMAGE_HYPERLINK in _categories(result)


def test_anchor_without_img_not_flagged_as_image_hyperlink() -> None:
    ctx = '<a href="https://example.com">'
    result = _analyze(_anchor("https://example.com", context=ctx))
    assert HyperlinkObservationCategory.IMAGE_HYPERLINK not in _categories(result)


def test_image_hyperlink_href_preserved() -> None:
    href = "https://example.com/landing"
    ctx = f'<a href="{href}"><img src="banner.png">'
    result = _analyze(_anchor(href, context=ctx))
    obs = next(
        o
        for o in result.observations
        if o.category is HyperlinkObservationCategory.IMAGE_HYPERLINK
    )
    assert obs.href == href


# ---------------------------------------------------------------------------
# BUTTON_LINK
# ---------------------------------------------------------------------------


def test_role_button_detected_as_button_link() -> None:
    ctx = '<a href="https://example.com" role="button">'
    result = _analyze(_anchor("https://example.com", context=ctx))
    assert HyperlinkObservationCategory.BUTTON_LINK in _categories(result)


def test_role_button_single_quotes_detected() -> None:
    ctx = "<a href=\"https://example.com\" role='button'>"
    result = _analyze(_anchor("https://example.com", context=ctx))
    assert HyperlinkObservationCategory.BUTTON_LINK in _categories(result)


def test_role_button_uppercase_detected() -> None:
    ctx = '<a href="https://example.com" role="BUTTON">'
    result = _analyze(_anchor("https://example.com", context=ctx))
    assert HyperlinkObservationCategory.BUTTON_LINK in _categories(result)


def test_anchor_without_role_button_not_flagged() -> None:
    ctx = '<a href="https://example.com" class="btn">'
    result = _analyze(_anchor("https://example.com", context=ctx))
    assert HyperlinkObservationCategory.BUTTON_LINK not in _categories(result)


def test_button_link_href_preserved() -> None:
    href = "https://example.com/action"
    ctx = f'<a href="{href}" role="button">'
    result = _analyze(_anchor(href, context=ctx))
    obs = next(
        o
        for o in result.observations
        if o.category is HyperlinkObservationCategory.BUTTON_LINK
    )
    assert obs.href == href


# ---------------------------------------------------------------------------
# ANCHOR_TEXT_MISMATCH — detect_anchor_text_mismatch helper
# ---------------------------------------------------------------------------


def test_mismatch_detected_when_text_url_differs_from_href() -> None:
    obs = detect_anchor_text_mismatch(
        href="https://evil.example.com/phish",
        anchor_text="https://legitimate.example.com",
    )
    assert obs is not None
    assert obs.category is HyperlinkObservationCategory.ANCHOR_TEXT_MISMATCH


def test_mismatch_href_preserved() -> None:
    href = "https://evil.example.com/phish"
    obs = detect_anchor_text_mismatch(href=href, anchor_text="https://bank.example.com")
    assert obs is not None
    assert obs.href == href


def test_mismatch_anchor_text_preserved() -> None:
    text = "https://bank.example.com"
    obs = detect_anchor_text_mismatch(href="https://evil.example.com", anchor_text=text)
    assert obs is not None
    assert obs.anchor_text == text


def test_mismatch_html_context_preserved() -> None:
    ctx = '<a href="https://evil.example.com">'
    obs = detect_anchor_text_mismatch(
        href="https://evil.example.com",
        anchor_text="https://bank.example.com",
        html_context=ctx,
    )
    assert obs is not None
    assert obs.html_context == ctx


def test_no_mismatch_when_text_matches_href() -> None:
    href = "https://example.com/page"
    obs = detect_anchor_text_mismatch(href=href, anchor_text=href)
    assert obs is None


def test_no_mismatch_when_anchor_text_has_no_url() -> None:
    obs = detect_anchor_text_mismatch(
        href="https://example.com", anchor_text="Click here"
    )
    assert obs is None


def test_no_mismatch_when_anchor_text_is_empty() -> None:
    obs = detect_anchor_text_mismatch(href="https://example.com", anchor_text="")
    assert obs is None


def test_mismatch_with_www_prefix_in_text() -> None:
    obs = detect_anchor_text_mismatch(
        href="https://evil.example.com",
        anchor_text="www.legitimate.example.com",
    )
    assert obs is not None
    assert obs.category is HyperlinkObservationCategory.ANCHOR_TEXT_MISMATCH


def test_mismatch_trailing_punctuation_ignored() -> None:
    # href and text are the same URL modulo trailing period — should not mismatch.
    obs = detect_anchor_text_mismatch(
        href="https://example.com",
        anchor_text="https://example.com.",
    )
    assert obs is None


# ---------------------------------------------------------------------------
# Multiple observations on one URL
# ---------------------------------------------------------------------------


def test_hidden_and_image_hyperlink_both_emitted() -> None:
    ctx = '<a href="https://example.com" style="display:none"><img src="x.png">'
    result = _analyze(_anchor("https://example.com", context=ctx))
    cats = _categories(result)
    assert HyperlinkObservationCategory.HIDDEN_URL in cats
    assert HyperlinkObservationCategory.IMAGE_HYPERLINK in cats


def test_button_and_image_hyperlink_both_emitted() -> None:
    ctx = '<a href="https://example.com" role="button"><img src="icon.png">'
    result = _analyze(_anchor("https://example.com", context=ctx))
    cats = _categories(result)
    assert HyperlinkObservationCategory.BUTTON_LINK in cats
    assert HyperlinkObservationCategory.IMAGE_HYPERLINK in cats


# ---------------------------------------------------------------------------
# Multiple URLs in one call
# ---------------------------------------------------------------------------


def test_multiple_urls_each_inspected_independently() -> None:
    result = _analyze(
        _anchor("javascript:void(0)"),
        _anchor("mailto:user@example.com"),
        _meta_refresh("https://redirect.example.com"),
    )
    cats = _categories(result)
    assert HyperlinkObservationCategory.JAVASCRIPT_LINK in cats
    assert HyperlinkObservationCategory.MAILTO_LINK in cats
    assert HyperlinkObservationCategory.META_REFRESH in cats


def test_normal_https_anchor_produces_no_observations() -> None:
    result = _analyze(_anchor("https://example.com"))
    assert result.observations == ()


def test_mixed_normal_and_notable_urls() -> None:
    result = _analyze(
        _anchor("https://example.com"),
        _anchor("javascript:void(0)"),
        _anchor("https://other.example.com"),
    )
    cats = _categories(result)
    assert cats == [HyperlinkObservationCategory.JAVASCRIPT_LINK]


# ---------------------------------------------------------------------------
# HTML context preservation
# ---------------------------------------------------------------------------


def test_html_context_preserved_on_javascript_link() -> None:
    ctx = '<a href="javascript:void(0)">'
    result = _analyze(_anchor("javascript:void(0)", context=ctx))
    obs = result.observations[0]
    assert obs.html_context == ctx


def test_html_context_preserved_on_mailto_link() -> None:
    ctx = '<a href="mailto:user@example.com">'
    result = _analyze(_anchor("mailto:user@example.com", context=ctx))
    obs = result.observations[0]
    assert obs.html_context == ctx


def test_html_context_none_when_not_supplied() -> None:
    result = _analyze(_anchor("javascript:void(0)"))
    obs = result.observations[0]
    assert obs.html_context is None


# ---------------------------------------------------------------------------
# Edge cases
# ---------------------------------------------------------------------------


def test_href_with_leading_whitespace_before_javascript_scheme() -> None:
    result = _analyze(_anchor("  javascript:void(0)"))
    assert HyperlinkObservationCategory.JAVASCRIPT_LINK in _categories(result)


def test_href_with_leading_whitespace_before_mailto_scheme() -> None:
    result = _analyze(_anchor("  mailto:user@example.com"))
    assert HyperlinkObservationCategory.MAILTO_LINK in _categories(result)


def test_non_html_source_urls_ignored() -> None:
    urls = (
        ExtractedUrl(
            raw_value="https://example.com",
            source=UrlExtractionSource.BODY_TEXT,
            position=0,
        ),
        ExtractedUrl(
            raw_value="https://example.com",
            source=UrlExtractionSource.JS_STRING,
            position=0,
        ),
        ExtractedUrl(
            raw_value="https://example.com",
            source=UrlExtractionSource.HTML_FORM,
            position=0,
        ),
    )
    result = DeterministicHyperlinkAnalyzer().analyze(urls)
    assert result.observations == ()
