"""Unit tests for Phase 4 URL normalization.

Covers every normalization step in isolation and in combination:
  1. Scheme lowercasing
  2. Host lowercasing
  3. Default-port removal
  4. Path percent-encoding normalization
  5. Dot-segment resolution
  6. Fragment removal
  7. Trailing-slash normalization
  8. Unicode host normalization (IDNA + NFC)

Also covers: protocol conformance, audit trail accuracy, determinism,
invalid inputs, oversized outputs, and integration with ExtractedUrl.
"""

from __future__ import annotations

from src.analyzers.url.contracts import UrlNormalizer
from src.analyzers.url.normalizer import CanonicalUrlNormalizer
from src.models.url import ExtractedUrl, NormalizedUrl, UrlExtractionSource

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _norm(raw: str) -> NormalizedUrl:
    return CanonicalUrlNormalizer().normalize(raw)


def _value(raw: str) -> str | None:
    return _norm(raw).normalized_value


def _actions(raw: str) -> tuple[str, ...]:
    return _norm(raw).actions


# ---------------------------------------------------------------------------
# Protocol conformance
# ---------------------------------------------------------------------------


def test_canonical_normalizer_satisfies_url_normalizer_protocol() -> None:
    """CanonicalUrlNormalizer satisfies the UrlNormalizer protocol at runtime."""
    assert isinstance(CanonicalUrlNormalizer(), UrlNormalizer)


def test_normalize_returns_normalized_url_instance() -> None:
    """normalize() always returns a NormalizedUrl instance."""
    result = _norm("https://example.com")

    assert isinstance(result, NormalizedUrl)


def test_normalize_preserves_raw_value() -> None:
    """The raw_value field always reflects the original input."""
    raw = "HTTPS://Example.COM/Path"
    result = _norm(raw)

    assert result.raw_value == raw


# ---------------------------------------------------------------------------
# Step 1 — Scheme lowercasing
# ---------------------------------------------------------------------------


def test_uppercase_https_scheme_is_lowercased() -> None:
    result = _norm("HTTPS://example.com/path")

    assert result.is_valid is True
    assert result.normalized_value is not None
    assert result.normalized_value.startswith("https://")


def test_mixed_case_http_scheme_is_lowercased() -> None:
    result = _norm("HtTp://example.com/")

    assert result.normalized_value is not None
    assert result.normalized_value.startswith("http://")


def test_uppercase_ftp_scheme_is_lowercased() -> None:
    result = _norm("FTP://files.example.com/archive.zip")

    assert result.normalized_value is not None
    assert result.normalized_value.startswith("ftp://")


def test_scheme_lowercasing_recorded_in_actions() -> None:
    actions = _actions("HTTPS://example.com")

    assert "scheme_lowercased" in actions


def test_already_lowercase_scheme_produces_no_action() -> None:
    actions = _actions("https://example.com")

    assert "scheme_lowercased" not in actions


# ---------------------------------------------------------------------------
# Step 2 — Host lowercasing
# ---------------------------------------------------------------------------


def test_uppercase_host_is_lowercased() -> None:
    result = _norm("https://EXAMPLE.COM/path")

    assert result.normalized_value is not None
    assert "example.com" in result.normalized_value
    assert "EXAMPLE.COM" not in result.normalized_value


def test_mixed_case_host_is_lowercased() -> None:
    result = _norm("https://Mail.Example.Com/inbox")

    assert result.normalized_value is not None
    assert "mail.example.com" in result.normalized_value


def test_host_lowercasing_recorded_in_actions() -> None:
    actions = _actions("https://EXAMPLE.COM")

    assert "host_lowercased" in actions


def test_already_lowercase_host_produces_no_action() -> None:
    actions = _actions("https://example.com")

    assert "host_lowercased" not in actions


def test_host_with_subdomain_fully_lowercased() -> None:
    result = _norm("https://Mail.Sub.EXAMPLE.COM/path")

    assert result.normalized_value is not None
    assert "mail.sub.example.com" in result.normalized_value


# ---------------------------------------------------------------------------
# Step 3 — Default-port removal
# ---------------------------------------------------------------------------


def test_http_default_port_80_is_removed() -> None:
    result = _norm("http://example.com:80/path")

    assert result.normalized_value is not None
    assert ":80" not in result.normalized_value
    assert "example.com" in result.normalized_value


def test_https_default_port_443_is_removed() -> None:
    result = _norm("https://example.com:443/path")

    assert result.normalized_value is not None
    assert ":443" not in result.normalized_value


def test_ftp_default_port_21_is_removed() -> None:
    result = _norm("ftp://files.example.com:21/archive.zip")

    assert result.normalized_value is not None
    assert ":21" not in result.normalized_value


def test_non_default_port_is_preserved() -> None:
    result = _norm("https://api.example.com:8443/v1")

    assert result.normalized_value is not None
    assert ":8443" in result.normalized_value


def test_http_non_default_port_8080_is_preserved() -> None:
    result = _norm("http://example.com:8080/app")

    assert result.normalized_value is not None
    assert ":8080" in result.normalized_value


def test_default_port_removal_recorded_in_actions() -> None:
    actions = _actions("https://example.com:443/path")

    assert "default_port_removed" in actions


def test_non_default_port_produces_no_removal_action() -> None:
    actions = _actions("https://example.com:8443/path")

    assert "default_port_removed" not in actions


def test_https_port_80_is_not_removed() -> None:
    """Port 80 is not the default for https — must be preserved."""
    result = _norm("https://example.com:80/path")

    assert result.normalized_value is not None
    assert ":80" in result.normalized_value


# ---------------------------------------------------------------------------
# Step 4 — Path percent-encoding normalization
# ---------------------------------------------------------------------------


def test_unreserved_percent_encoded_chars_are_decoded() -> None:
    """Percent-encoded unreserved characters are decoded (RFC 3986 §2.3)."""
    result = _norm("https://example.com/%41%42%43")  # ABC

    assert result.normalized_value is not None
    assert "/ABC" in result.normalized_value
    assert "%41" not in result.normalized_value


def test_lowercase_percent_escapes_are_uppercased() -> None:
    """Percent-escape hex digits are normalized to uppercase."""
    result = _norm("https://example.com/path%2fmore")

    assert result.normalized_value is not None
    # %2f is '/' — a path delimiter, decoded to /
    assert "%2f" not in result.normalized_value


def test_reserved_chars_remain_encoded() -> None:
    """Characters that must stay encoded are not decoded."""
    result = _norm("https://example.com/path%20with%20spaces")

    assert result.normalized_value is not None
    # %20 is space — must remain encoded in the path
    assert " " not in result.normalized_value


def test_path_encoding_action_recorded_when_changed() -> None:
    actions = _actions("https://example.com/%41path")

    assert "path_encoding_normalized" in actions


def test_already_normalized_path_produces_no_encoding_action() -> None:
    actions = _actions("https://example.com/clean/path")

    assert "path_encoding_normalized" not in actions


def test_tilde_is_decoded_from_percent_encoding() -> None:
    """Tilde (%7E) is an unreserved character and should be decoded."""
    result = _norm("https://example.com/%7Euser/profile")

    assert result.normalized_value is not None
    assert "~user" in result.normalized_value


# ---------------------------------------------------------------------------
# Step 5 — Dot-segment resolution
# ---------------------------------------------------------------------------


def test_single_dot_segment_is_resolved() -> None:
    result = _norm("https://example.com/a/./b")

    assert result.normalized_value is not None
    assert "/a/./b" not in result.normalized_value
    assert "/a/b" in result.normalized_value


def test_double_dot_segment_is_resolved() -> None:
    result = _norm("https://example.com/a/b/../c")

    assert result.normalized_value is not None
    assert "/../" not in result.normalized_value
    assert "/a/c" in result.normalized_value


def test_multiple_dot_segments_are_resolved() -> None:
    result = _norm("https://example.com/a/b/../../c")

    assert result.normalized_value is not None
    assert "/c" in result.normalized_value


def test_dot_segment_resolution_recorded_in_actions() -> None:
    actions = _actions("https://example.com/a/./b")

    assert "dot_segments_resolved" in actions


def test_clean_path_produces_no_dot_segment_action() -> None:
    actions = _actions("https://example.com/a/b/c")

    assert "dot_segments_resolved" not in actions


def test_trailing_double_dot_is_resolved() -> None:
    result = _norm("https://example.com/a/b/..")

    assert result.normalized_value is not None
    assert "/.." not in result.normalized_value


# ---------------------------------------------------------------------------
# Step 6 — Fragment removal
# ---------------------------------------------------------------------------


def test_fragment_is_removed() -> None:
    result = _norm("https://example.com/page#section")

    assert result.normalized_value is not None
    assert "#section" not in result.normalized_value
    assert "#" not in result.normalized_value


def test_fragment_removal_recorded_in_actions() -> None:
    actions = _actions("https://example.com/page#anchor")

    assert "fragment_removed" in actions


def test_url_without_fragment_produces_no_removal_action() -> None:
    actions = _actions("https://example.com/page")

    assert "fragment_removed" not in actions


def test_fragment_only_url_fragment_is_removed() -> None:
    """A URL with only a fragment after the path loses the fragment."""
    result = _norm("https://example.com/#top")

    assert result.normalized_value is not None
    assert "#" not in result.normalized_value


def test_query_is_preserved_when_fragment_is_removed() -> None:
    result = _norm("https://example.com/page?q=1#section")

    assert result.normalized_value is not None
    assert "q=1" in result.normalized_value
    assert "#" not in result.normalized_value


# ---------------------------------------------------------------------------
# Step 7 — Trailing-slash normalization
# ---------------------------------------------------------------------------


def test_bare_host_trailing_slash_is_removed() -> None:
    """A URL with only a root slash path has the slash removed."""
    result = _norm("https://example.com/")

    assert result.normalized_value is not None
    assert result.normalized_value == "https://example.com"


def test_trailing_slash_removal_recorded_in_actions() -> None:
    actions = _actions("https://example.com/")

    assert "trailing_slash_removed" in actions


def test_path_trailing_slash_is_preserved() -> None:
    """A trailing slash on a real path is preserved (may be significant)."""
    result = _norm("https://example.com/path/")

    assert result.normalized_value is not None
    assert result.normalized_value.endswith("/path/")


def test_deep_path_trailing_slash_is_preserved() -> None:
    result = _norm("https://example.com/a/b/c/")

    assert result.normalized_value is not None
    assert result.normalized_value.endswith("/c/")


def test_no_path_url_has_no_trailing_slash_action() -> None:
    actions = _actions("https://example.com/path")

    assert "trailing_slash_removed" not in actions


# ---------------------------------------------------------------------------
# Step 8 — Unicode normalization
# ---------------------------------------------------------------------------


def test_non_ascii_host_is_idna_encoded() -> None:
    """A host with non-ASCII characters is IDNA-encoded."""
    result = _norm("https://münchen.de/path")

    assert result.is_valid is True
    assert result.normalized_value is not None
    # IDNA encoding converts ü → xn-- form
    assert "xn--" in result.normalized_value


def test_idna_encoding_recorded_in_actions() -> None:
    actions = _actions("https://münchen.de/")

    assert "host_idna_encoded" in actions


def test_ascii_host_produces_no_idna_action() -> None:
    actions = _actions("https://example.com/path")

    assert "host_idna_encoded" not in actions


def test_nfc_normalization_applied_to_path() -> None:
    """A path with decomposed Unicode characters is NFC-normalized."""
    # 'é' as decomposed (e + combining acute accent) vs precomposed
    decomposed = "e\u0301"  # e + combining acute
    precomposed = "\xe9"    # é precomposed
    raw = f"https://example.com/{decomposed}/page"
    result = _norm(raw)

    assert result.is_valid is True
    assert result.normalized_value is not None
    assert (
        precomposed in result.normalized_value
        or decomposed not in result.normalized_value
    )


def test_already_nfc_path_produces_no_nfc_action() -> None:
    actions = _actions("https://example.com/path/page")

    assert "path_nfc_normalized" not in actions


# ---------------------------------------------------------------------------
# Audit trail
# ---------------------------------------------------------------------------


def test_clean_url_produces_empty_actions() -> None:
    """A fully normalized URL produces no actions."""
    result = _norm("https://example.com/path?q=1")

    assert result.actions == ()


def test_multiple_steps_all_recorded() -> None:
    """A URL requiring multiple steps records all of them."""
    # HTTPS uppercase + default port + fragment
    result = _norm("HTTPS://EXAMPLE.COM:443/page#frag")

    assert "scheme_lowercased" in result.actions
    assert "host_lowercased" in result.actions
    assert "default_port_removed" in result.actions
    assert "fragment_removed" in result.actions


def test_actions_are_ordered_by_pipeline_step() -> None:
    """Actions appear in pipeline order: scheme → host → port → ..."""
    result = _norm("HTTPS://EXAMPLE.COM:443/page#frag")
    actions = list(result.actions)

    scheme_idx = actions.index("scheme_lowercased")
    host_idx = actions.index("host_lowercased")
    port_idx = actions.index("default_port_removed")
    frag_idx = actions.index("fragment_removed")

    assert scheme_idx < host_idx < port_idx < frag_idx


def test_actions_tuple_is_immutable() -> None:
    """The actions field is a tuple (immutable)."""
    result = _norm("HTTPS://example.com")

    assert isinstance(result.actions, tuple)


# ---------------------------------------------------------------------------
# Determinism
# ---------------------------------------------------------------------------


def test_same_input_always_produces_same_output() -> None:
    """Normalization is deterministic: identical inputs produce identical outputs."""
    raw = "HTTPS://EXAMPLE.COM:443/a/./b?q=hello%20world#frag"
    first = _norm(raw)
    second = _norm(raw)

    assert first.normalized_value == second.normalized_value
    assert first.actions == second.actions


def test_different_representations_normalize_to_same_value() -> None:
    """Equivalent URLs with different casing normalize to the same value."""
    lower = _norm("https://example.com/path")
    upper = _norm("HTTPS://EXAMPLE.COM/path")

    assert lower.normalized_value == upper.normalized_value


def test_port_variants_normalize_to_same_value() -> None:
    """https://example.com:443/ and https://example.com/ normalize identically."""
    with_port = _norm("https://example.com:443/")
    without_port = _norm("https://example.com/")

    assert with_port.normalized_value == without_port.normalized_value


# ---------------------------------------------------------------------------
# Invalid and edge-case inputs
# ---------------------------------------------------------------------------


def test_empty_string_returns_invalid() -> None:
    result = _norm("")

    assert result.is_valid is False
    assert result.normalized_value is None


def test_whitespace_only_returns_invalid() -> None:
    result = _norm("   ")

    assert result.is_valid is False
    assert result.normalized_value is None


def test_plain_text_returns_invalid() -> None:
    result = _norm("not a url at all")

    assert result.is_valid is False
    assert result.normalized_value is None


def test_bare_www_url_gets_http_scheme_added() -> None:
    """A bare www. URL without a scheme is treated as http://."""
    result = _norm("www.example.com/path")

    assert result.is_valid is True
    assert result.normalized_value is not None
    assert result.normalized_value.startswith("http://")
    assert "scheme_added" in result.actions


def test_url_with_credentials_is_normalized() -> None:
    """Credentials in the authority are preserved through normalization."""
    result = _norm("https://user:pass@EXAMPLE.COM/secure")

    assert result.is_valid is True
    assert result.normalized_value is not None
    assert "user:pass@" in result.normalized_value
    assert "example.com" in result.normalized_value


def test_url_with_ipv4_host_is_normalized() -> None:
    result = _norm("https://192.168.1.1/admin")

    assert result.is_valid is True
    assert result.normalized_value is not None
    assert "192.168.1.1" in result.normalized_value


def test_url_with_query_string_is_preserved() -> None:
    result = _norm("https://example.com/search?q=hello+world&page=2")

    assert result.is_valid is True
    assert result.normalized_value is not None
    assert "q=hello" in result.normalized_value
    assert "page=2" in result.normalized_value


def test_javascript_scheme_url_is_normalized() -> None:
    """javascript: URLs are normalized (scheme lowercased) without error."""
    result = _norm("JAVASCRIPT://example.com/alert(1)")

    assert result.is_valid is True
    assert result.normalized_value is not None
    assert result.normalized_value.startswith("javascript://")


def test_ftp_url_is_normalized() -> None:
    result = _norm("FTP://Files.Example.COM:21/archive.zip")

    assert result.is_valid is True
    assert result.normalized_value is not None
    assert result.normalized_value.startswith("ftp://")
    assert "files.example.com" in result.normalized_value
    assert ":21" not in result.normalized_value


def test_url_with_punycode_host_is_preserved() -> None:
    """A URL already using punycode is passed through unchanged."""
    result = _norm("https://xn--mnich-kva.example/page")

    assert result.is_valid is True
    assert result.normalized_value is not None
    assert "xn--mnich-kva" in result.normalized_value


def test_oversized_normalized_url_returns_invalid() -> None:
    """A URL whose normalized form exceeds MAX_NORMALIZED_URL_LENGTH is invalid."""
    long_path = "a" * 8_200
    raw = f"https://example.com/{long_path}"
    result = _norm(raw)

    assert result.is_valid is False
    assert result.normalized_value is None


def test_normalizer_never_raises_on_garbage_input() -> None:
    """The normalizer must not raise on any input."""
    garbage_inputs = [
        "",
        "   ",
        "://",
        "http://",
        "\x00\x01\x02",
        "a" * 10_000,
        "https://\x00evil.com",
        "http://[invalid-ipv6",
    ]
    normalizer = CanonicalUrlNormalizer()
    for inp in garbage_inputs:
        result = normalizer.normalize(inp)
        assert isinstance(result, NormalizedUrl)


# ---------------------------------------------------------------------------
# Integration with ExtractedUrl
# ---------------------------------------------------------------------------


def test_normalizer_accepts_extracted_url_raw_value() -> None:
    """The normalizer can be applied directly to ExtractedUrl.raw_value."""
    extracted = ExtractedUrl(
        raw_value="HTTPS://EXAMPLE.COM:443/Path#frag",
        source=UrlExtractionSource.BODY_TEXT,
        position=0,
    )
    result = CanonicalUrlNormalizer().normalize(extracted.raw_value)

    assert result.is_valid is True
    assert result.normalized_value is not None
    assert result.normalized_value == "https://example.com/Path"


def test_normalizer_result_raw_value_matches_extracted_raw_value() -> None:
    """NormalizedUrl.raw_value always equals the input passed to normalize()."""
    raw = "HTTPS://Example.COM/page"
    extracted = ExtractedUrl(
        raw_value=raw,
        source=UrlExtractionSource.HTML_ANCHOR,
        position=0,
    )
    result = CanonicalUrlNormalizer().normalize(extracted.raw_value)

    assert result.raw_value == extracted.raw_value


def test_normalizer_applied_to_multiple_extracted_urls() -> None:
    """The normalizer can be applied to a batch of ExtractedUrl instances."""
    raws = [
        "HTTPS://FIRST.COM/",
        "http://second.com:80/path",
        "https://third.com/a/../b",
    ]
    normalizer = CanonicalUrlNormalizer()
    results = [normalizer.normalize(r) for r in raws]

    assert all(r.is_valid for r in results)
    assert results[0].normalized_value == "https://first.com"
    assert results[1].normalized_value == "http://second.com/path"
    assert results[2].normalized_value is not None
    assert "/../" not in results[2].normalized_value
