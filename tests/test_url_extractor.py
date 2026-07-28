"""Unit tests for Phase 4 URL extraction.

Covers:
- RegexUrlExtractor: plain-text body and subject (all original tests preserved)
- HtmlUrlExtractor: all 9 HTML extraction sources
- CompositeUrlExtractor: deduplication, ordering, combined sources
- Protocol conformance for all three extractors
- html_context preservation
- Edge cases and adversarial inputs
"""

from __future__ import annotations

from src.analyzers.url.contracts import UrlExtractor
from src.analyzers.url.extractor import (
    CompositeUrlExtractor,
    HtmlUrlExtractor,
    RegexUrlExtractor,
)
from src.models.email import EmailHeader, EmailInput
from src.models.url import UrlExtractionSource

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _email(
    body: str,
    subject: str = "Test subject",
    sender: str = "sender@example.com",
    reply_to: str | None = None,
) -> EmailInput:
    return EmailInput(
        header=EmailHeader(
            message_id="<test@example.com>",
            sender=sender,
            recipients=["recipient@example.net"],
            subject=subject,
            sent_at="2026-01-01T00:00:00Z",
            reply_to=reply_to,
        ),
        body_text=body,
    )


# ---------------------------------------------------------------------------
# Protocol conformance
# ---------------------------------------------------------------------------


def test_regex_extractor_satisfies_url_extractor_protocol() -> None:
    assert isinstance(RegexUrlExtractor(), UrlExtractor)


def test_html_extractor_satisfies_url_extractor_protocol() -> None:
    assert isinstance(HtmlUrlExtractor(), UrlExtractor)


def test_composite_extractor_satisfies_url_extractor_protocol() -> None:
    assert isinstance(CompositeUrlExtractor(), UrlExtractor)


# ---------------------------------------------------------------------------
# RegexUrlExtractor — body_text extraction
# ---------------------------------------------------------------------------


def test_extracts_https_url_from_body() -> None:
    results = RegexUrlExtractor().extract(
        _email("Click here: https://example.com/path?q=1")
    )

    assert len(results) == 1
    assert results[0].raw_value == "https://example.com/path?q=1"
    assert results[0].source is UrlExtractionSource.BODY_TEXT
    assert results[0].position == 12


def test_extracts_http_url_from_body() -> None:
    results = RegexUrlExtractor().extract(
        _email("Visit http://example.com for details.")
    )

    assert len(results) == 1
    assert results[0].raw_value == "http://example.com"


def test_extracts_multiple_urls_from_body() -> None:
    body = "First: https://first.example.com " "Second: https://second.example.com/page"
    results = RegexUrlExtractor().extract(_email(body))

    assert len(results) == 2
    assert results[0].raw_value == "https://first.example.com"
    assert results[1].raw_value == "https://second.example.com/page"


def test_extracts_ftp_url_from_body() -> None:
    results = RegexUrlExtractor().extract(
        _email("Download from ftp://files.example.com/archive.zip")
    )

    assert len(results) == 1
    assert results[0].raw_value.startswith("ftp://")


def test_extracts_www_url_without_scheme() -> None:
    results = RegexUrlExtractor().extract(
        _email("Visit www.example.com for more information.")
    )

    assert len(results) == 1
    assert results[0].raw_value == "www.example.com"


def test_extracts_url_with_query_and_fragment() -> None:
    url = "https://example.com/page?key=value&other=123#section"
    results = RegexUrlExtractor().extract(_email(f"See {url}"))

    assert len(results) == 1
    assert results[0].raw_value == url


def test_extracts_url_with_port() -> None:
    results = RegexUrlExtractor().extract(
        _email("API at https://api.example.com:8443/v1/endpoint")
    )

    assert len(results) == 1
    assert ":8443" in results[0].raw_value


def test_extracts_url_with_path_depth() -> None:
    url = "https://example.com/a/b/c/d/e/f"
    results = RegexUrlExtractor().extract(_email(url))

    assert results[0].raw_value == url


def test_extracts_url_with_credentials() -> None:
    url = "https://user:pass@example.com/secure"
    results = RegexUrlExtractor().extract(_email(url))

    assert len(results) == 1
    assert "user:pass@" in results[0].raw_value


def test_extracts_javascript_scheme_url() -> None:
    results = RegexUrlExtractor().extract(
        _email("Click: javascript://example.com/alert(1)")
    )

    assert len(results) == 1
    assert results[0].raw_value.startswith("javascript://")


def test_extracts_data_scheme_url() -> None:
    results = RegexUrlExtractor().extract(
        _email("Image: data://text/html;base64,PHNjcmlwdD4=")
    )

    assert len(results) == 1
    assert results[0].raw_value.startswith("data://")


# ---------------------------------------------------------------------------
# RegexUrlExtractor — subject extraction
# ---------------------------------------------------------------------------


def test_extracts_url_from_subject() -> None:
    results = RegexUrlExtractor().extract(
        _email(body="No URLs here.", subject="Check https://example.com now")
    )

    url_results = [r for r in results if r.source is UrlExtractionSource.SUBJECT]
    assert len(url_results) == 1
    assert url_results[0].raw_value == "https://example.com"


def test_extracts_urls_from_both_body_and_subject() -> None:
    results = RegexUrlExtractor().extract(
        _email(
            body="Body: https://body.example.com",
            subject="Subject: https://subject.example.com",
        )
    )

    sources = {r.source for r in results}
    assert UrlExtractionSource.BODY_TEXT in sources
    assert UrlExtractionSource.SUBJECT in sources


def test_body_urls_appear_before_subject_urls() -> None:
    results = RegexUrlExtractor().extract(
        _email(
            body="https://body.example.com",
            subject="https://subject.example.com",
        )
    )

    assert results[0].source is UrlExtractionSource.BODY_TEXT
    assert results[1].source is UrlExtractionSource.SUBJECT


# ---------------------------------------------------------------------------
# RegexUrlExtractor — position preservation
# ---------------------------------------------------------------------------


def test_position_reflects_character_offset_in_source_field() -> None:
    body = "Hello world https://example.com end"
    results = RegexUrlExtractor().extract(_email(body))

    assert results[0].position == body.index("https://")


def test_multiple_urls_have_correct_positions() -> None:
    body = "https://first.com and https://second.com"
    results = RegexUrlExtractor().extract(_email(body))

    assert results[0].position == 0
    assert results[1].position == body.index("https://second.com")


# ---------------------------------------------------------------------------
# RegexUrlExtractor — trailing punctuation stripping
# ---------------------------------------------------------------------------


def test_trailing_period_is_stripped() -> None:
    results = RegexUrlExtractor().extract(_email("Visit https://example.com."))

    assert results[0].raw_value == "https://example.com"


def test_trailing_comma_is_stripped() -> None:
    results = RegexUrlExtractor().extract(
        _email("See https://example.com, for details")
    )

    assert results[0].raw_value == "https://example.com"


def test_trailing_closing_paren_is_stripped() -> None:
    results = RegexUrlExtractor().extract(_email("(see https://example.com)"))

    assert results[0].raw_value == "https://example.com"


def test_trailing_exclamation_is_stripped() -> None:
    results = RegexUrlExtractor().extract(_email("Click https://example.com!"))

    assert results[0].raw_value == "https://example.com"


def test_url_with_legitimate_trailing_slash_is_preserved() -> None:
    results = RegexUrlExtractor().extract(_email("Visit https://example.com/path/"))

    assert results[0].raw_value == "https://example.com/path/"


# ---------------------------------------------------------------------------
# RegexUrlExtractor — edge cases
# ---------------------------------------------------------------------------


def test_empty_body_produces_no_results() -> None:
    results = RegexUrlExtractor().extract(_email("No links here at all."))

    assert results == ()


def test_email_address_is_not_extracted_as_url() -> None:
    results = RegexUrlExtractor().extract(
        _email("Contact us at support@example.com for help.")
    )

    assert results == ()


def test_bare_domain_without_www_is_not_extracted() -> None:
    results = RegexUrlExtractor().extract(
        _email("Visit example.com for more information.")
    )

    assert results == ()


def test_url_surrounded_by_angle_brackets_is_extracted() -> None:
    results = RegexUrlExtractor().extract(_email("Link: <https://example.com/path>"))

    assert len(results) == 1
    assert "example.com" in results[0].raw_value


def test_oversized_url_is_silently_discarded() -> None:
    long_path = "a" * 8_200
    body = f"https://example.com/{long_path}"
    results = RegexUrlExtractor().extract(_email(body))

    assert results == ()


def test_url_cap_per_source_is_respected() -> None:
    urls = " ".join(f"https://example{i}.com" for i in range(600))
    extractor = RegexUrlExtractor(max_urls_per_source=10)
    results = extractor.extract(_email(urls))

    body_results = [r for r in results if r.source is UrlExtractionSource.BODY_TEXT]
    assert len(body_results) == 10


def test_duplicate_urls_are_preserved_as_separate_occurrences() -> None:
    url = "https://example.com"
    body = f"{url} and again {url}"
    results = RegexUrlExtractor().extract(_email(body))

    assert len(results) == 2
    assert results[0].position != results[1].position


def test_url_with_unicode_path_is_extracted() -> None:
    results = RegexUrlExtractor().extract(_email("Visit https://example.com/über/path"))

    assert len(results) == 1
    assert "example.com" in results[0].raw_value


def test_url_with_ip_address_host_is_extracted() -> None:
    results = RegexUrlExtractor().extract(
        _email("Connect to https://192.168.1.1/admin")
    )

    assert len(results) == 1
    assert "192.168.1.1" in results[0].raw_value


def test_url_with_punycode_host_is_extracted() -> None:
    results = RegexUrlExtractor().extract(
        _email("Visit https://xn--mnich-kva.example/page")
    )

    assert len(results) == 1
    assert "xn--mnich-kva" in results[0].raw_value


def test_url_with_subdomain_chain_is_extracted() -> None:
    url = "https://a.b.c.d.example.com/path"
    results = RegexUrlExtractor().extract(_email(url))

    assert len(results) == 1
    assert results[0].raw_value == url


def test_mixed_case_scheme_is_extracted() -> None:
    results = RegexUrlExtractor().extract(_email("Visit HTTPS://example.com/page"))

    assert len(results) == 1
    assert "example.com" in results[0].raw_value


def test_url_in_html_anchor_text_is_extracted() -> None:
    results = RegexUrlExtractor().extract(
        _email('Click <a href="https://example.com/page">here</a>')
    )

    assert len(results) == 1
    assert results[0].raw_value == "https://example.com/page"


def test_newline_separated_urls_are_each_extracted() -> None:
    body = "https://first.example.com\nhttps://second.example.com"
    results = RegexUrlExtractor().extract(_email(body))

    assert len(results) == 2


def test_extract_returns_tuple_not_list() -> None:
    results = RegexUrlExtractor().extract(_email("https://example.com"))

    assert isinstance(results, tuple)


def test_empty_subject_with_url_in_body_only() -> None:
    results = RegexUrlExtractor().extract(
        _email(body="https://example.com", subject="No URL here")
    )

    subject_results = [r for r in results if r.source is UrlExtractionSource.SUBJECT]
    assert subject_results == []


def test_url_with_percent_encoded_characters_is_extracted() -> None:
    url = "https://example.com/path%20with%20spaces?q=hello%20world"
    results = RegexUrlExtractor().extract(_email(url))

    assert len(results) == 1
    assert results[0].raw_value == url


# ---------------------------------------------------------------------------
# HtmlUrlExtractor — anchor href
# ---------------------------------------------------------------------------


def test_html_extracts_anchor_href() -> None:
    html = '<a href="https://example.com/page">Click</a>'
    results = HtmlUrlExtractor().extract(_email(html))

    assert any(
        r.raw_value == "https://example.com/page"
        and r.source is UrlExtractionSource.HTML_ANCHOR
        for r in results
    )


def test_html_anchor_href_context_is_preserved() -> None:
    html = '<a href="https://example.com">link</a>'
    results = HtmlUrlExtractor().extract(_email(html))

    anchor = next(r for r in results if r.source is UrlExtractionSource.HTML_ANCHOR)
    assert anchor.html_context is not None
    assert "href" in anchor.html_context


def test_html_extracts_multiple_anchors() -> None:
    html = (
        '<a href="https://first.example.com">1</a>'
        '<a href="https://second.example.com">2</a>'
    )
    results = HtmlUrlExtractor().extract(_email(html))

    anchors = [r for r in results if r.source is UrlExtractionSource.HTML_ANCHOR]
    assert len(anchors) == 2


def test_html_anchor_without_href_produces_no_result() -> None:
    html = '<a name="top">anchor</a>'
    results = HtmlUrlExtractor().extract(_email(html))

    assert not any(r.source is UrlExtractionSource.HTML_ANCHOR for r in results)


def test_html_empty_anchor_href_produces_no_result() -> None:
    html = '<a href="">anchor</a>'
    results = HtmlUrlExtractor().extract(_email(html))

    assert not any(r.source is UrlExtractionSource.HTML_ANCHOR for r in results)


def test_html_whitespace_anchor_href_produces_no_result() -> None:
    html = '<a href="   ">anchor</a>'
    results = HtmlUrlExtractor().extract(_email(html))

    assert not any(r.source is UrlExtractionSource.HTML_ANCHOR for r in results)


# ---------------------------------------------------------------------------
# HtmlUrlExtractor — image src
# ---------------------------------------------------------------------------


def test_html_extracts_image_src() -> None:
    html = '<img src="https://cdn.example.com/image.png" alt="logo">'
    results = HtmlUrlExtractor().extract(_email(html))

    assert any(
        r.raw_value == "https://cdn.example.com/image.png"
        and r.source is UrlExtractionSource.HTML_IMAGE
        for r in results
    )


def test_html_image_context_is_preserved() -> None:
    html = '<img src="https://cdn.example.com/img.png">'
    results = HtmlUrlExtractor().extract(_email(html))

    img = next(r for r in results if r.source is UrlExtractionSource.HTML_IMAGE)
    assert img.html_context is not None
    assert "img" in img.html_context


def test_html_extracts_image_srcset() -> None:
    html = (
        '<img srcset="https://cdn.example.com/small.png 1x,'
        ' https://cdn.example.com/large.png 2x">'
    )
    results = HtmlUrlExtractor().extract(_email(html))

    image_urls = {
        r.raw_value for r in results if r.source is UrlExtractionSource.HTML_IMAGE
    }
    assert "https://cdn.example.com/small.png" in image_urls
    assert "https://cdn.example.com/large.png" in image_urls


# ---------------------------------------------------------------------------
# HtmlUrlExtractor — form action
# ---------------------------------------------------------------------------


def test_html_extracts_form_action() -> None:
    html = '<form action="https://submit.example.com/login" method="post"></form>'
    results = HtmlUrlExtractor().extract(_email(html))

    assert any(
        r.raw_value == "https://submit.example.com/login"
        and r.source is UrlExtractionSource.HTML_FORM
        for r in results
    )


def test_html_form_context_is_preserved() -> None:
    html = '<form action="https://submit.example.com/login"></form>'
    results = HtmlUrlExtractor().extract(_email(html))

    form = next(r for r in results if r.source is UrlExtractionSource.HTML_FORM)
    assert form.html_context is not None
    assert "form" in form.html_context


# ---------------------------------------------------------------------------
# HtmlUrlExtractor — meta refresh
# ---------------------------------------------------------------------------


def test_html_extracts_meta_refresh_url() -> None:
    html = '<meta http-equiv="refresh" content="5; url=https://redirect.example.com">'
    results = HtmlUrlExtractor().extract(_email(html))

    assert any(
        r.raw_value == "https://redirect.example.com"
        and r.source is UrlExtractionSource.META_REFRESH
        for r in results
    )


def test_html_meta_refresh_without_url_produces_no_result() -> None:
    html = '<meta http-equiv="refresh" content="5">'
    results = HtmlUrlExtractor().extract(_email(html))

    assert not any(r.source is UrlExtractionSource.META_REFRESH for r in results)


def test_html_meta_non_refresh_is_ignored() -> None:
    html = '<meta name="description" content="https://example.com">'
    results = HtmlUrlExtractor().extract(_email(html))

    assert not any(r.source is UrlExtractionSource.META_REFRESH for r in results)


# ---------------------------------------------------------------------------
# HtmlUrlExtractor — inline style
# ---------------------------------------------------------------------------


def test_html_extracts_inline_style_url() -> None:
    html = '<div style="background-image: url(https://bg.example.com/img.png)">x</div>'
    results = HtmlUrlExtractor().extract(_email(html))

    assert any(
        r.raw_value == "https://bg.example.com/img.png"
        and r.source is UrlExtractionSource.INLINE_STYLE
        for r in results
    )


def test_html_inline_style_url_with_quotes() -> None:
    html = "<div style=\"background: url('https://bg.example.com/img.png')\">x</div>"
    results = HtmlUrlExtractor().extract(_email(html))

    assert any(
        "bg.example.com" in r.raw_value and r.source is UrlExtractionSource.INLINE_STYLE
        for r in results
    )


def test_html_inline_style_context_is_preserved() -> None:
    html = '<p style="background: url(https://bg.example.com/img.png)">text</p>'
    results = HtmlUrlExtractor().extract(_email(html))

    style_result = next(
        r for r in results if r.source is UrlExtractionSource.INLINE_STYLE
    )
    assert style_result.html_context is not None


# ---------------------------------------------------------------------------
# HtmlUrlExtractor — CSS link href
# ---------------------------------------------------------------------------


def test_html_extracts_link_href_as_css_url() -> None:
    html = '<link rel="stylesheet" href="https://cdn.example.com/style.css">'
    results = HtmlUrlExtractor().extract(_email(html))

    assert any(
        r.raw_value == "https://cdn.example.com/style.css"
        and r.source is UrlExtractionSource.CSS_URL
        for r in results
    )


# ---------------------------------------------------------------------------
# HtmlUrlExtractor — SVG references
# ---------------------------------------------------------------------------


def test_html_extracts_svg_image_href() -> None:
    html = '<svg><image href="https://cdn.example.com/sprite.svg"/></svg>'
    results = HtmlUrlExtractor().extract(_email(html))

    assert any(
        "sprite.svg" in r.raw_value and r.source is UrlExtractionSource.SVG_REFERENCE
        for r in results
    )


def test_html_extracts_svg_use_href() -> None:
    html = '<svg><use href="https://cdn.example.com/icons.svg#icon"/></svg>'
    results = HtmlUrlExtractor().extract(_email(html))

    assert any(
        "icons.svg" in r.raw_value and r.source is UrlExtractionSource.SVG_REFERENCE
        for r in results
    )


# ---------------------------------------------------------------------------
# HtmlUrlExtractor — JavaScript string literals
# ---------------------------------------------------------------------------


def test_html_extracts_js_string_literal_url() -> None:
    html = '<script>var url = "https://api.example.com/endpoint";</script>'
    results = HtmlUrlExtractor().extract(_email(html))

    assert any(
        r.raw_value == "https://api.example.com/endpoint"
        and r.source is UrlExtractionSource.JS_STRING
        for r in results
    )


def test_html_extracts_js_single_quoted_string_url() -> None:
    html = "<script>window.location = 'https://redirect.example.com';</script>"
    results = HtmlUrlExtractor().extract(_email(html))

    assert any(
        "redirect.example.com" in r.raw_value
        and r.source is UrlExtractionSource.JS_STRING
        for r in results
    )


def test_html_js_string_has_no_html_context() -> None:
    html = '<script>var u = "https://api.example.com";</script>'
    results = HtmlUrlExtractor().extract(_email(html))

    js = next(r for r in results if r.source is UrlExtractionSource.JS_STRING)
    assert js.html_context is None


# ---------------------------------------------------------------------------
# HtmlUrlExtractor — edge cases
# ---------------------------------------------------------------------------


def test_html_extractor_returns_tuple() -> None:
    results = HtmlUrlExtractor().extract(_email("<p>no urls</p>"))

    assert isinstance(results, tuple)


def test_html_extractor_on_plain_text_produces_no_html_results() -> None:
    results = HtmlUrlExtractor().extract(_email("Just plain text, no HTML."))

    assert results == ()


def test_html_extractor_handles_malformed_html_without_raising() -> None:
    html = "<a href='https://example.com'><b>unclosed"
    results = HtmlUrlExtractor().extract(_email(html))

    # Should not raise; may or may not find the URL depending on parser recovery
    assert isinstance(results, tuple)


def test_html_extractor_discards_oversized_url() -> None:
    long = "a" * 8_200
    html = f'<a href="https://example.com/{long}">x</a>'
    results = HtmlUrlExtractor().extract(_email(html))

    assert not any(r.source is UrlExtractionSource.HTML_ANCHOR for r in results)


def test_html_context_is_truncated_to_max_length() -> None:
    long_attr = "x" * 600
    html = f'<a href="https://example.com" data-extra="{long_attr}">link</a>'
    results = HtmlUrlExtractor().extract(_email(html))

    anchor = next(r for r in results if r.source is UrlExtractionSource.HTML_ANCHOR)
    assert anchor.html_context is not None
    assert len(anchor.html_context) <= 512


# ---------------------------------------------------------------------------
# CompositeUrlExtractor — deduplication
# ---------------------------------------------------------------------------


def test_composite_deduplicates_same_url_same_source() -> None:
    # The same URL appearing twice in body_text produces two regex hits,
    # but composite deduplication keeps only the first.
    url = "https://example.com"
    body = f"{url} and again {url}"
    results = CompositeUrlExtractor().extract(_email(body))

    body_hits = [r for r in results if r.source is UrlExtractionSource.BODY_TEXT]
    # RegexUrlExtractor preserves both occurrences; composite deduplicates
    # by (raw_value, source) so only one survives.
    assert len(body_hits) == 1


def test_composite_keeps_same_url_from_different_sources() -> None:
    # Same URL in body_text (regex) and as an anchor href (HTML) — different
    # sources, so both are kept.
    url = "https://example.com/page"
    html = f'{url} <a href="{url}">link</a>'
    results = CompositeUrlExtractor().extract(_email(html))

    sources = {r.source for r in results if url in r.raw_value}
    assert UrlExtractionSource.BODY_TEXT in sources
    assert UrlExtractionSource.HTML_ANCHOR in sources


def test_composite_plain_text_results_appear_before_html_results() -> None:
    html = "https://text.example.com " '<a href="https://anchor.example.com">link</a>'
    results = CompositeUrlExtractor().extract(_email(html))

    text_idx = next(
        i for i, r in enumerate(results) if r.source is UrlExtractionSource.BODY_TEXT
    )
    html_idx = next(
        i for i, r in enumerate(results) if r.source is UrlExtractionSource.HTML_ANCHOR
    )
    assert text_idx < html_idx


def test_composite_returns_tuple() -> None:
    results = CompositeUrlExtractor().extract(_email("https://example.com"))

    assert isinstance(results, tuple)


def test_composite_empty_body_produces_no_results() -> None:
    results = CompositeUrlExtractor().extract(_email("No links here."))

    assert results == ()


def test_composite_collects_from_all_html_sources() -> None:
    html = """
    <a href="https://anchor.example.com">link</a>
    <img src="https://img.example.com/pic.png">
    <form action="https://form.example.com/submit"></form>
    <meta http-equiv="refresh" content="0; url=https://meta.example.com">
    <link href="https://css.example.com/style.css">
    <div style="background: url(https://style.example.com/bg.png)">x</div>
    <script>var u = "https://js.example.com/api";</script>
    """
    results = CompositeUrlExtractor().extract(_email(html))

    sources_found = {r.source for r in results}
    assert UrlExtractionSource.HTML_ANCHOR in sources_found
    assert UrlExtractionSource.HTML_IMAGE in sources_found
    assert UrlExtractionSource.HTML_FORM in sources_found
    assert UrlExtractionSource.META_REFRESH in sources_found
    assert UrlExtractionSource.CSS_URL in sources_found
    assert UrlExtractionSource.INLINE_STYLE in sources_found
    assert UrlExtractionSource.JS_STRING in sources_found


def test_composite_subject_urls_are_included() -> None:
    results = CompositeUrlExtractor().extract(
        _email(body="<p>body</p>", subject="See https://subject.example.com")
    )

    assert any(r.source is UrlExtractionSource.SUBJECT for r in results)
