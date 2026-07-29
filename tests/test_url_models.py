"""Unit tests for Phase 4 URL data contracts.

Verifies that every model enforces its schema, rejects invalid input,
accepts valid input, and exposes no risk-score or verdict fields.
"""

from __future__ import annotations

import pytest
from pydantic import ValidationError

from src.models.url import (
    EmailUrlAnalysisResult,
    ExtractedUrl,
    NormalizedUrl,
    ParsedUrlComponents,
    SuspiciousPatternCategory,
    SuspiciousPatternMatch,
    UnicodeScriptCategory,
    UrlExtractionSource,
    UrlHostAnalysis,
    UrlHostType,
    UrlIntelligenceResult,
    UrlReputationStub,
    UrlScheme,
    UrlShortenerAnalysis,
    UrlStructuralFeatures,
    UrlUnicodeAnalysis,
)

# ---------------------------------------------------------------------------
# ExtractedUrl
# ---------------------------------------------------------------------------


def test_extracted_url_accepts_valid_input() -> None:
    """A well-formed ExtractedUrl stores all fields correctly."""
    url = ExtractedUrl(
        raw_value="https://example.com/path",
        source=UrlExtractionSource.BODY_TEXT,
        position=42,
    )

    assert url.raw_value == "https://example.com/path"
    assert url.source is UrlExtractionSource.BODY_TEXT
    assert url.position == 42


def test_extracted_url_rejects_empty_raw_value() -> None:
    """An empty raw_value violates the min_length=1 constraint."""
    with pytest.raises(ValidationError):
        ExtractedUrl(
            raw_value="",
            source=UrlExtractionSource.BODY_TEXT,
            position=0,
        )


def test_extracted_url_rejects_negative_position() -> None:
    """A negative position violates the ge=0 constraint."""
    with pytest.raises(ValidationError):
        ExtractedUrl(
            raw_value="https://example.com",
            source=UrlExtractionSource.BODY_TEXT,
            position=-1,
        )


def test_extracted_url_rejects_oversized_raw_value() -> None:
    """A raw_value exceeding MAX_RAW_URL_LENGTH is rejected."""
    with pytest.raises(ValidationError):
        ExtractedUrl(
            raw_value="https://example.com/" + "a" * 8_200,
            source=UrlExtractionSource.BODY_TEXT,
            position=0,
        )


def test_extracted_url_is_frozen() -> None:
    """ExtractedUrl instances are immutable."""
    url = ExtractedUrl(
        raw_value="https://example.com",
        source=UrlExtractionSource.BODY_TEXT,
        position=0,
    )
    with pytest.raises(ValidationError):
        url.position = 1


def test_extracted_url_all_sources_are_valid() -> None:
    """Every UrlExtractionSource value is accepted."""
    for source in UrlExtractionSource:
        url = ExtractedUrl(
            raw_value="https://example.com",
            source=source,
            position=0,
        )
        assert url.source is source


# ---------------------------------------------------------------------------
# ParsedUrlComponents
# ---------------------------------------------------------------------------


def test_parsed_url_components_defaults_to_unparseable() -> None:
    """Default construction produces an unparseable result with no components."""
    components = ParsedUrlComponents()

    assert components.is_parseable is False
    assert components.scheme is None
    assert components.host is None
    assert components.port is None
    assert components.path is None
    assert components.query is None
    assert components.fragment is None
    assert components.username is None
    assert components.password is None


def test_parsed_url_components_accepts_full_url() -> None:
    """All component fields can be populated simultaneously."""
    components = ParsedUrlComponents(
        scheme="https",
        username="user",
        password="pass",
        host="example.com",
        port=8443,
        path="/api/v1",
        query="key=value",
        fragment="section",
        is_parseable=True,
    )

    assert components.scheme == "https"
    assert components.host == "example.com"
    assert components.port == 8443
    assert components.is_parseable is True


def test_parsed_url_components_rejects_invalid_port() -> None:
    """A port value above 65535 is rejected."""
    with pytest.raises(ValidationError):
        ParsedUrlComponents(host="example.com", port=70_000, is_parseable=True)


def test_parsed_url_components_rejects_negative_port() -> None:
    """A negative port value is rejected."""
    with pytest.raises(ValidationError):
        ParsedUrlComponents(host="example.com", port=-1, is_parseable=True)


# ---------------------------------------------------------------------------
# NormalizedUrl
# ---------------------------------------------------------------------------


def test_normalized_url_valid_result() -> None:
    """A valid normalization result stores canonical form and actions."""
    normalized = NormalizedUrl(
        raw_value="HTTPS://Example.COM/Path",
        normalized_value="https://example.com/Path",
        is_valid=True,
        actions=("scheme_lowercased", "host_lowercased"),
    )

    assert normalized.is_valid is True
    assert normalized.normalized_value == "https://example.com/Path"
    assert "scheme_lowercased" in normalized.actions


def test_normalized_url_invalid_result_has_no_canonical_form() -> None:
    """An invalid normalization result has no normalized_value."""
    normalized = NormalizedUrl(
        raw_value="not a url",
        is_valid=False,
    )

    assert normalized.is_valid is False
    assert normalized.normalized_value is None
    assert normalized.actions == ()


# ---------------------------------------------------------------------------
# UrlHostAnalysis
# ---------------------------------------------------------------------------


def test_url_host_analysis_defaults() -> None:
    """Default construction produces a safe empty host analysis."""
    host = UrlHostAnalysis()

    assert host.host_type is UrlHostType.EMPTY
    assert host.raw_host is None
    assert host.is_ip_address is False
    assert host.is_localhost is False
    assert host.subdomain_depth == 0


def test_url_host_analysis_domain_type() -> None:
    """A domain host is correctly represented."""
    host = UrlHostAnalysis(
        raw_host="mail.example.com",
        host_type=UrlHostType.DOMAIN,
        normalized_host="mail.example.com",
        registered_domain="example.com",
        effective_tld="com",
        subdomain="mail",
        subdomain_depth=1,
    )

    assert host.host_type is UrlHostType.DOMAIN
    assert host.registered_domain == "example.com"
    assert host.subdomain_depth == 1


def test_url_host_analysis_ipv4_type() -> None:
    """An IPv4 host is correctly represented."""
    host = UrlHostAnalysis(
        raw_host="192.168.1.1",
        host_type=UrlHostType.IP_V4,
        normalized_host="192.168.1.1",
        is_ip_address=True,
    )

    assert host.host_type is UrlHostType.IP_V4
    assert host.is_ip_address is True


# ---------------------------------------------------------------------------
# UrlUnicodeAnalysis
# ---------------------------------------------------------------------------


def test_url_unicode_analysis_defaults() -> None:
    """Default construction produces a safe all-false result."""
    analysis = UrlUnicodeAnalysis()

    assert analysis.contains_non_ascii is False
    assert analysis.has_mixed_scripts is False
    assert analysis.detected_scripts == ()
    assert analysis.has_rtl_characters is False


def test_url_unicode_analysis_mixed_scripts() -> None:
    """Mixed-script detection is correctly represented."""
    analysis = UrlUnicodeAnalysis(
        contains_non_ascii=True,
        has_mixed_scripts=True,
        detected_scripts=(
            UnicodeScriptCategory.LATIN,
            UnicodeScriptCategory.CYRILLIC,
        ),
    )

    assert analysis.has_mixed_scripts is True
    assert UnicodeScriptCategory.CYRILLIC in analysis.detected_scripts


# ---------------------------------------------------------------------------
# UrlStructuralFeatures
# ---------------------------------------------------------------------------


def test_url_structural_features_all_counts_non_negative() -> None:
    """All count fields must be non-negative."""
    features = UrlStructuralFeatures(
        total_length=32,
        host_length=11,
        path_length=5,
        path_depth=2,
        query_parameter_count=3,
        fragment_length=0,
        subdomain_count=1,
        dot_count=2,
        hyphen_count=0,
        digit_count=1,
        at_sign_count=0,
        percent_encoded_count=0,
    )

    assert features.total_length == 32
    assert features.path_depth == 2
    assert features.query_parameter_count == 3


def test_url_structural_features_rejects_negative_counts() -> None:
    """Negative count values are rejected by the model."""
    with pytest.raises(ValidationError):
        UrlStructuralFeatures(
            total_length=-1,
            host_length=0,
            path_length=0,
            path_depth=0,
            query_parameter_count=0,
            fragment_length=0,
            subdomain_count=0,
            dot_count=0,
            hyphen_count=0,
            digit_count=0,
            at_sign_count=0,
            percent_encoded_count=0,
        )


# ---------------------------------------------------------------------------
# UrlShortenerAnalysis
# ---------------------------------------------------------------------------


def test_url_shortener_analysis_not_shortened() -> None:
    """Default construction represents a non-shortened URL."""
    analysis = UrlShortenerAnalysis()

    assert analysis.is_shortened is False
    assert analysis.matched_shortener_host is None


def test_url_shortener_analysis_shortened() -> None:
    """A shortened URL records the matched host."""
    analysis = UrlShortenerAnalysis(
        is_shortened=True,
        matched_shortener_host="bit.ly",
    )

    assert analysis.is_shortened is True
    assert analysis.matched_shortener_host == "bit.ly"


# ---------------------------------------------------------------------------
# SuspiciousPatternMatch
# ---------------------------------------------------------------------------


def test_suspicious_pattern_match_all_categories_valid() -> None:
    """Every SuspiciousPatternCategory value can be stored in a match."""
    for category in SuspiciousPatternCategory:
        match = SuspiciousPatternMatch(
            category=category,
            detail=f"Observed: {category.value}",
        )
        assert match.category is category


def test_suspicious_pattern_match_rejects_empty_detail() -> None:
    """An empty detail string violates the min_length=1 constraint."""
    with pytest.raises(ValidationError):
        SuspiciousPatternMatch(
            category=SuspiciousPatternCategory.IP_ADDRESS_HOST,
            detail="",
        )


# ---------------------------------------------------------------------------
# UrlReputationStub
# ---------------------------------------------------------------------------


def test_url_reputation_stub_default() -> None:
    """The reputation stub defaults to unqueried."""
    stub = UrlReputationStub()

    assert stub.queried is False


def test_url_reputation_stub_rejects_extra_fields() -> None:
    """The reputation stub enforces extra='forbid'."""
    with pytest.raises(ValidationError):
        UrlReputationStub(queried=False, score=0.5)  # type: ignore[call-arg]


# ---------------------------------------------------------------------------
# UrlIntelligenceResult
# ---------------------------------------------------------------------------


def test_url_intelligence_result_minimal_construction() -> None:
    """A result can be constructed with only the required extracted field."""
    extracted = ExtractedUrl(
        raw_value="https://example.com",
        source=UrlExtractionSource.BODY_TEXT,
        position=0,
    )
    result = UrlIntelligenceResult(extracted=extracted)

    assert result.extracted.raw_value == "https://example.com"
    assert result.components.is_parseable is False
    assert result.normalized is None
    assert result.suspicious_patterns == ()
    assert result.reputation.queried is False


def test_url_intelligence_result_contains_no_verdict_fields() -> None:
    """The result contract has no risk score or phishing verdict field."""
    extracted = ExtractedUrl(
        raw_value="https://example.com",
        source=UrlExtractionSource.BODY_TEXT,
        position=0,
    )
    result = UrlIntelligenceResult(extracted=extracted)
    serialized = result.model_dump()

    assert "risk_score" not in serialized
    assert "phishing_probability" not in serialized
    assert "verdict" not in serialized
    assert "is_malicious" not in serialized


def test_url_intelligence_result_is_frozen() -> None:
    """UrlIntelligenceResult instances are immutable."""
    extracted = ExtractedUrl(
        raw_value="https://example.com",
        source=UrlExtractionSource.BODY_TEXT,
        position=0,
    )
    result = UrlIntelligenceResult(extracted=extracted)

    with pytest.raises(ValidationError):
        result.extracted = extracted


def test_url_intelligence_result_rejects_extra_fields() -> None:
    """Extra fields are rejected by the strict schema."""
    extracted = ExtractedUrl(
        raw_value="https://example.com",
        source=UrlExtractionSource.BODY_TEXT,
        position=0,
    )
    with pytest.raises(ValidationError):
        UrlIntelligenceResult(  # type: ignore[call-arg]
            extracted=extracted,
            unknown_field="value",
        )


# ---------------------------------------------------------------------------
# EmailUrlAnalysisResult
# ---------------------------------------------------------------------------


def test_email_url_analysis_result_empty() -> None:
    """An email with no URLs produces a valid empty result."""
    result = EmailUrlAnalysisResult(
        message_id="<msg-001@example.com>",
        total_urls_found=0,
        unique_hosts=0,
    )

    assert result.urls == ()
    assert result.total_urls_found == 0
    assert result.unique_hosts == 0


def test_email_url_analysis_result_with_urls() -> None:
    """An email result correctly stores multiple URL intelligence results."""
    extracted = ExtractedUrl(
        raw_value="https://example.com",
        source=UrlExtractionSource.BODY_TEXT,
        position=0,
    )
    url_result = UrlIntelligenceResult(extracted=extracted)
    result = EmailUrlAnalysisResult(
        message_id="<msg-001@example.com>",
        urls=(url_result,),
        total_urls_found=1,
        unique_hosts=1,
    )

    assert len(result.urls) == 1
    assert result.total_urls_found == 1


def test_email_url_analysis_result_rejects_negative_counts() -> None:
    """Negative URL counts are rejected."""
    with pytest.raises(ValidationError):
        EmailUrlAnalysisResult(
            message_id="<msg@example.com>",
            total_urls_found=-1,
            unique_hosts=0,
        )


def test_url_scheme_enum_covers_expected_values() -> None:
    """UrlScheme covers all expected scheme values."""
    expected = {"http", "https", "ftp", "mailto", "data", "javascript", "other"}
    actual = {scheme.value for scheme in UrlScheme}

    assert actual == expected


def test_extracted_url_accepts_html_context() -> None:
    """html_context is stored when provided."""
    url = ExtractedUrl(
        raw_value="https://example.com",
        source=UrlExtractionSource.HTML_ANCHOR,
        position=0,
        html_context='<a href="https://example.com">',
    )

    assert url.html_context is not None
    assert "href" in url.html_context


def test_extracted_url_html_context_defaults_to_none() -> None:
    """html_context is None when not supplied."""
    url = ExtractedUrl(
        raw_value="https://example.com",
        source=UrlExtractionSource.BODY_TEXT,
        position=0,
    )

    assert url.html_context is None


def test_url_extraction_source_covers_html_sources() -> None:
    """UrlExtractionSource includes all HTML extraction source values."""
    expected_html = {
        "html_anchor",
        "html_image",
        "html_form",
        "css_url",
        "meta_refresh",
        "inline_style",
        "svg_reference",
        "js_string",
    }
    actual = {s.value for s in UrlExtractionSource}

    assert expected_html.issubset(actual)
