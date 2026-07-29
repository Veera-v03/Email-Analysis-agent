"""Unit tests for Phase 4 URL feature extraction.

Covers every feature extracted by StructuralUrlFeatureExtractor:

Lengths
    total_length, host_length, path_length

Structural counts
    path_depth, query_parameter_count, fragment_length,
    subdomain_count, dot_count, hyphen_count, digit_count,
    at_sign_count, percent_encoded_count

Boolean flags
    has_credentials, has_port, has_fragment, has_query,
    uses_default_port, path_has_double_extension

Ratio / entropy
    digit_ratio, symbol_ratio, entropy_score

Also covers: protocol conformance, model contract (frozen, extra=forbid,
no verdict fields), empty/minimal inputs, and integration with the
normalizer pipeline.
"""

from __future__ import annotations

import math

import pytest
from pydantic import ValidationError

from src.analyzers.url.contracts import UrlFeatureExtractor
from src.analyzers.url.features import StructuralUrlFeatureExtractor
from src.models.url import ParsedUrlComponents, UrlStructuralFeatures

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _components(
    scheme: str | None = "https",
    host: str | None = "example.com",
    path: str | None = "/path",
    query: str | None = None,
    fragment: str | None = None,
    port: int | None = None,
    username: str | None = None,
    password: str | None = None,
    subdomain: str | None = None,
    registered_domain: str | None = None,
    tld: str | None = None,
    *,
    is_parseable: bool = True,
) -> ParsedUrlComponents:
    return ParsedUrlComponents(
        scheme=scheme,
        host=host,
        path=path,
        query=query,
        fragment=fragment,
        port=port,
        username=username,
        password=password,
        subdomain=subdomain,
        registered_domain=registered_domain,
        tld=tld,
        is_parseable=is_parseable,
    )


def _extract(components: ParsedUrlComponents) -> UrlStructuralFeatures:
    return StructuralUrlFeatureExtractor().extract(components)


# ---------------------------------------------------------------------------
# Protocol conformance
# ---------------------------------------------------------------------------


def test_structural_extractor_satisfies_url_feature_extractor_protocol() -> None:
    """StructuralUrlFeatureExtractor satisfies UrlFeatureExtractor at runtime."""
    assert isinstance(StructuralUrlFeatureExtractor(), UrlFeatureExtractor)


def test_extract_returns_url_structural_features_instance() -> None:
    """extract() always returns a UrlStructuralFeatures instance."""
    result = _extract(_components())

    assert isinstance(result, UrlStructuralFeatures)


# ---------------------------------------------------------------------------
# Model contract
# ---------------------------------------------------------------------------


def test_result_is_frozen() -> None:
    """UrlStructuralFeatures instances are immutable."""
    result = _extract(_components())

    with pytest.raises((ValidationError, TypeError)):
        result.total_length = 0


def test_result_rejects_extra_fields() -> None:
    """UrlStructuralFeatures enforces extra='forbid'."""
    with pytest.raises(ValidationError):
        UrlStructuralFeatures(  # type: ignore[call-arg]
            total_length=10,
            host_length=7,
            path_length=5,
            path_depth=1,
            query_parameter_count=0,
            fragment_length=0,
            subdomain_count=0,
            dot_count=1,
            hyphen_count=0,
            digit_count=0,
            at_sign_count=0,
            percent_encoded_count=0,
            unknown_field="bad",
        )


def test_result_contains_no_verdict_fields() -> None:
    """The result model has no risk score or security verdict fields."""
    result = _extract(_components())
    serialized = result.model_dump()

    assert "risk_score" not in serialized
    assert "verdict" not in serialized
    assert "is_malicious" not in serialized
    assert "phishing_probability" not in serialized


# ---------------------------------------------------------------------------
# total_length
# ---------------------------------------------------------------------------


def test_total_length_matches_reconstructed_url() -> None:
    """total_length equals the character count of the reconstructed URL."""
    c = _components(
        scheme="https", host="example.com", path="/page", query=None, fragment=None
    )
    result = _extract(c)

    assert result.total_length == len("https://example.com/page")


def test_total_length_includes_query_and_fragment() -> None:
    c = _components(path="/p", query="q=1", fragment="sec")
    result = _extract(c)

    assert result.total_length == len("https://example.com/p?q=1#sec")


def test_total_length_zero_for_empty_components() -> None:
    """All-None components produce total_length of 0."""
    c = _components(
        scheme=None,
        host=None,
        path=None,
        query=None,
        fragment=None,
        is_parseable=False,
    )
    result = _extract(c)

    assert result.total_length == 0


# ---------------------------------------------------------------------------
# host_length
# ---------------------------------------------------------------------------


def test_host_length_matches_host_string() -> None:
    c = _components(host="mail.example.com")
    result = _extract(c)

    assert result.host_length == len("mail.example.com")


def test_host_length_zero_when_no_host() -> None:
    c = _components(scheme="https", host=None, path="/path")
    result = _extract(c)

    assert result.host_length == 0


def test_host_length_for_ip_address() -> None:
    c = _components(host="192.168.1.1")
    result = _extract(c)

    assert result.host_length == len("192.168.1.1")


# ---------------------------------------------------------------------------
# path_length
# ---------------------------------------------------------------------------


def test_path_length_matches_path_string() -> None:
    c = _components(path="/api/v1/endpoint")
    result = _extract(c)

    assert result.path_length == len("/api/v1/endpoint")


def test_path_length_zero_when_no_path() -> None:
    c = _components(path=None)
    result = _extract(c)

    assert result.path_length == 0


def test_path_length_for_deep_path() -> None:
    c = _components(path="/a/b/c/d/e")
    result = _extract(c)

    assert result.path_length == len("/a/b/c/d/e")


# ---------------------------------------------------------------------------
# path_depth
# ---------------------------------------------------------------------------


def test_path_depth_counts_non_empty_segments() -> None:
    c = _components(path="/a/b/c")
    result = _extract(c)

    assert result.path_depth == 3


def test_path_depth_zero_for_root_path() -> None:
    c = _components(path="/")
    result = _extract(c)

    assert result.path_depth == 0


def test_path_depth_zero_for_no_path() -> None:
    c = _components(path=None)
    result = _extract(c)

    assert result.path_depth == 0


def test_path_depth_single_segment() -> None:
    c = _components(path="/page")
    result = _extract(c)

    assert result.path_depth == 1


def test_path_depth_ignores_trailing_slash() -> None:
    """A trailing slash does not add an extra depth level."""
    c = _components(path="/a/b/")
    result = _extract(c)

    assert result.path_depth == 2


# ---------------------------------------------------------------------------
# query_parameter_count
# ---------------------------------------------------------------------------


def test_query_parameter_count_single_param() -> None:
    c = _components(query="key=value")
    result = _extract(c)

    assert result.query_parameter_count == 1


def test_query_parameter_count_multiple_params() -> None:
    c = _components(query="a=1&b=2&c=3")
    result = _extract(c)

    assert result.query_parameter_count == 3


def test_query_parameter_count_zero_when_no_query() -> None:
    c = _components(query=None)
    result = _extract(c)

    assert result.query_parameter_count == 0


def test_query_parameter_count_empty_string() -> None:
    c = _components(query="")
    result = _extract(c)

    assert result.query_parameter_count == 0


# ---------------------------------------------------------------------------
# fragment_length
# ---------------------------------------------------------------------------


def test_fragment_length_matches_fragment_string() -> None:
    c = _components(fragment="section-2")
    result = _extract(c)

    assert result.fragment_length == len("section-2")


def test_fragment_length_zero_when_no_fragment() -> None:
    c = _components(fragment=None)
    result = _extract(c)

    assert result.fragment_length == 0


# ---------------------------------------------------------------------------
# subdomain_count
# ---------------------------------------------------------------------------


def test_subdomain_count_single_subdomain() -> None:
    c = _components(host="mail.example.com", subdomain="mail")
    result = _extract(c)

    assert result.subdomain_count == 1


def test_subdomain_count_multiple_subdomains() -> None:
    c = _components(host="a.b.c.example.com", subdomain="a.b.c")
    result = _extract(c)

    assert result.subdomain_count == 3


def test_subdomain_count_zero_when_no_subdomain() -> None:
    c = _components(host="example.com", subdomain=None)
    result = _extract(c)

    assert result.subdomain_count == 0


def test_subdomain_count_uses_components_subdomain_field() -> None:
    """When subdomain is set on components, it takes precedence."""
    c = _components(host="a.b.example.com", subdomain="a.b")
    result = _extract(c)

    assert result.subdomain_count == 2


# ---------------------------------------------------------------------------
# dot_count
# ---------------------------------------------------------------------------


def test_dot_count_counts_all_dots_in_url() -> None:
    c = _components(host="sub.example.com", path="/path.html")
    result = _extract(c)

    full = "https://sub.example.com/path.html"
    assert result.dot_count == full.count(".")


def test_dot_count_zero_for_empty_url() -> None:
    c = _components(scheme=None, host=None, path=None, is_parseable=False)
    result = _extract(c)

    assert result.dot_count == 0


# ---------------------------------------------------------------------------
# hyphen_count
# ---------------------------------------------------------------------------


def test_hyphen_count_counts_all_hyphens() -> None:
    c = _components(host="my-site.example-domain.com", path="/some-path")
    result = _extract(c)

    full = "https://my-site.example-domain.com/some-path"
    assert result.hyphen_count == full.count("-")


def test_hyphen_count_zero_when_no_hyphens() -> None:
    c = _components(host="example.com", path="/path")
    result = _extract(c)

    assert result.hyphen_count == 0


# ---------------------------------------------------------------------------
# digit_count
# ---------------------------------------------------------------------------


def test_digit_count_counts_all_digits_in_url() -> None:
    c = _components(host="example123.com", path="/page1/item2")
    result = _extract(c)

    full = "https://example123.com/page1/item2"
    assert result.digit_count == sum(1 for ch in full if ch.isdigit())


def test_digit_count_zero_for_no_digits() -> None:
    c = _components(host="example.com", path="/path")
    result = _extract(c)

    assert result.digit_count == 0


# ---------------------------------------------------------------------------
# at_sign_count
# ---------------------------------------------------------------------------


def test_at_sign_count_with_credentials() -> None:
    c = _components(username="user", password="pass")
    result = _extract(c)

    assert result.at_sign_count == 1


def test_at_sign_count_zero_without_credentials() -> None:
    c = _components(username=None, password=None)
    result = _extract(c)

    assert result.at_sign_count == 0


# ---------------------------------------------------------------------------
# percent_encoded_count
# ---------------------------------------------------------------------------


def test_percent_encoded_count_single_sequence() -> None:
    c = _components(path="/path%20with%20spaces")
    result = _extract(c)

    assert result.percent_encoded_count == 2


def test_percent_encoded_count_zero_when_none() -> None:
    c = _components(path="/clean/path")
    result = _extract(c)

    assert result.percent_encoded_count == 0


def test_percent_encoded_count_in_query() -> None:
    c = _components(path="/search", query="q=hello%20world%21")
    result = _extract(c)

    assert result.percent_encoded_count == 2


# ---------------------------------------------------------------------------
# has_credentials
# ---------------------------------------------------------------------------


def test_has_credentials_true_when_username_present() -> None:
    c = _components(username="user")
    result = _extract(c)

    assert result.has_credentials is True


def test_has_credentials_true_when_password_present() -> None:
    c = _components(username="user", password="secret")
    result = _extract(c)

    assert result.has_credentials is True


def test_has_credentials_false_when_no_auth() -> None:
    c = _components(username=None, password=None)
    result = _extract(c)

    assert result.has_credentials is False


# ---------------------------------------------------------------------------
# has_port
# ---------------------------------------------------------------------------


def test_has_port_true_when_port_present() -> None:
    c = _components(port=8443)
    result = _extract(c)

    assert result.has_port is True


def test_has_port_false_when_no_port() -> None:
    c = _components(port=None)
    result = _extract(c)

    assert result.has_port is False


# ---------------------------------------------------------------------------
# has_fragment
# ---------------------------------------------------------------------------


def test_has_fragment_true_when_fragment_present() -> None:
    c = _components(fragment="section")
    result = _extract(c)

    assert result.has_fragment is True


def test_has_fragment_false_when_no_fragment() -> None:
    c = _components(fragment=None)
    result = _extract(c)

    assert result.has_fragment is False


# ---------------------------------------------------------------------------
# has_query
# ---------------------------------------------------------------------------


def test_has_query_true_when_query_present() -> None:
    c = _components(query="key=value")
    result = _extract(c)

    assert result.has_query is True


def test_has_query_false_when_no_query() -> None:
    c = _components(query=None)
    result = _extract(c)

    assert result.has_query is False


# ---------------------------------------------------------------------------
# uses_default_port
# ---------------------------------------------------------------------------


def test_uses_default_port_true_for_http_80() -> None:
    c = _components(scheme="http", port=80)
    result = _extract(c)

    assert result.uses_default_port is True


def test_uses_default_port_true_for_https_443() -> None:
    c = _components(scheme="https", port=443)
    result = _extract(c)

    assert result.uses_default_port is True


def test_uses_default_port_true_for_ftp_21() -> None:
    c = _components(scheme="ftp", host="files.example.com", port=21)
    result = _extract(c)

    assert result.uses_default_port is True


def test_uses_default_port_false_for_non_default() -> None:
    c = _components(scheme="https", port=8443)
    result = _extract(c)

    assert result.uses_default_port is False


def test_uses_default_port_false_when_no_port() -> None:
    c = _components(scheme="https", port=None)
    result = _extract(c)

    assert result.uses_default_port is False


def test_uses_default_port_false_for_wrong_scheme_port_combo() -> None:
    """Port 80 on https is not a default port."""
    c = _components(scheme="https", port=80)
    result = _extract(c)

    assert result.uses_default_port is False


# ---------------------------------------------------------------------------
# path_has_double_extension
# ---------------------------------------------------------------------------


def test_path_has_double_extension_true() -> None:
    c = _components(path="/file.php.jpg")
    result = _extract(c)

    assert result.path_has_double_extension is True


def test_path_has_double_extension_false_for_single_extension() -> None:
    c = _components(path="/file.jpg")
    result = _extract(c)

    assert result.path_has_double_extension is False


def test_path_has_double_extension_false_for_no_extension() -> None:
    c = _components(path="/path/to/page")
    result = _extract(c)

    assert result.path_has_double_extension is False


def test_path_has_double_extension_true_for_exe_zip() -> None:
    c = _components(path="/download/payload.exe.zip")
    result = _extract(c)

    assert result.path_has_double_extension is True


def test_path_has_double_extension_false_for_no_path() -> None:
    c = _components(path=None)
    result = _extract(c)

    assert result.path_has_double_extension is False


# ---------------------------------------------------------------------------
# digit_ratio
# ---------------------------------------------------------------------------


def test_digit_ratio_is_zero_for_no_digits() -> None:
    c = _components(host="example.com", path="/path")
    result = _extract(c)

    assert result.digit_ratio == 0.0


def test_digit_ratio_is_between_zero_and_one() -> None:
    c = _components(host="123.456.com", path="/789")
    result = _extract(c)

    assert 0.0 <= result.digit_ratio <= 1.0


def test_digit_ratio_correct_value() -> None:
    """digit_ratio == digit_count / total_length."""
    c = _components(host="example.com", path="/page1")
    result = _extract(c)

    expected = result.digit_count / result.total_length
    assert abs(result.digit_ratio - expected) < 1e-9


def test_digit_ratio_zero_for_empty_url() -> None:
    c = _components(scheme=None, host=None, path=None, is_parseable=False)
    result = _extract(c)

    assert result.digit_ratio == 0.0


# ---------------------------------------------------------------------------
# symbol_ratio
# ---------------------------------------------------------------------------


def test_symbol_ratio_is_between_zero_and_one() -> None:
    c = _components(host="example.com", path="/path?q=1#frag")
    result = _extract(c)

    assert 0.0 <= result.symbol_ratio <= 1.0


def test_symbol_ratio_greater_than_zero_for_url_with_symbols() -> None:
    """A URL with slashes, dots, and colons has a non-zero symbol ratio."""
    c = _components(host="example.com", path="/path")
    result = _extract(c)

    assert result.symbol_ratio > 0.0


def test_symbol_ratio_zero_for_empty_url() -> None:
    c = _components(scheme=None, host=None, path=None, is_parseable=False)
    result = _extract(c)

    assert result.symbol_ratio == 0.0


def test_symbol_ratio_correct_value() -> None:
    """symbol_ratio == non-alphanumeric-non-space count / total_length."""
    import re

    c = _components(host="example.com", path="/path")
    result = _extract(c)

    full = "https://example.com/path"
    expected = len(re.findall(r"[^A-Za-z0-9\s]", full)) / len(full)
    assert abs(result.symbol_ratio - expected) < 1e-9


# ---------------------------------------------------------------------------
# entropy_score
# ---------------------------------------------------------------------------


def test_entropy_score_is_non_negative() -> None:
    c = _components()
    result = _extract(c)

    assert result.entropy_score >= 0.0


def test_entropy_score_is_at_most_eight() -> None:
    """Shannon entropy of a string over a byte alphabet is at most 8 bits."""
    c = _components(host="example.com", path="/path?q=random&x=123")
    result = _extract(c)

    assert result.entropy_score <= 8.0


def test_entropy_score_zero_for_empty_url() -> None:
    c = _components(scheme=None, host=None, path=None, is_parseable=False)
    result = _extract(c)

    assert result.entropy_score == 0.0


def test_entropy_score_higher_for_random_looking_url() -> None:
    """A URL with high character variety has higher entropy than a simple one."""
    simple = _extract(_components(host="aaa.aaa", path="/aaa"))
    complex_ = _extract(
        _components(host="xK9mP2.example.com", path="/aB3cD4eF5?q=zY7wV6")
    )

    assert complex_.entropy_score > simple.entropy_score


def test_entropy_score_correct_value() -> None:
    """entropy_score matches the Shannon entropy formula."""
    c = _components(scheme="https", host="example.com", path="/path")
    result = _extract(c)

    full = "https://example.com/path"
    freq: dict[str, int] = {}
    for ch in full:
        freq[ch] = freq.get(ch, 0) + 1
    n = len(full)
    expected = -sum((v / n) * math.log2(v / n) for v in freq.values())
    assert abs(result.entropy_score - expected) < 1e-9


# ---------------------------------------------------------------------------
# Unparseable / minimal components
# ---------------------------------------------------------------------------


def test_unparseable_components_return_all_zeros() -> None:
    """An unparseable URL produces a valid result with all counts at zero."""
    c = _components(
        scheme=None,
        host=None,
        path=None,
        query=None,
        fragment=None,
        is_parseable=False,
    )
    result = _extract(c)

    assert result.total_length == 0
    assert result.host_length == 0
    assert result.path_length == 0
    assert result.path_depth == 0
    assert result.query_parameter_count == 0
    assert result.fragment_length == 0
    assert result.subdomain_count == 0
    assert result.dot_count == 0
    assert result.hyphen_count == 0
    assert result.digit_count == 0
    assert result.at_sign_count == 0
    assert result.percent_encoded_count == 0
    assert result.has_credentials is False
    assert result.has_port is False
    assert result.has_fragment is False
    assert result.has_query is False
    assert result.uses_default_port is False
    assert result.path_has_double_extension is False
    assert result.digit_ratio == 0.0
    assert result.symbol_ratio == 0.0
    assert result.entropy_score == 0.0


def test_scheme_only_components_produce_valid_result() -> None:
    """Components with only a scheme do not raise."""
    c = _components(scheme="https", host=None, path=None)
    result = _extract(c)

    assert isinstance(result, UrlStructuralFeatures)


# ---------------------------------------------------------------------------
# Integration — full URL pipeline
# ---------------------------------------------------------------------------


def test_features_from_full_url_components() -> None:
    """A fully populated components object produces correct feature values."""
    c = _components(
        scheme="https",
        host="mail.example.com",
        path="/inbox/message",
        query="id=42&folder=sent",
        fragment="top",
        port=None,
        subdomain="mail",
    )
    result = _extract(c)

    assert result.path_depth == 2
    assert result.query_parameter_count == 2
    assert result.has_fragment is True
    assert result.has_query is True
    assert result.has_port is False
    assert result.subdomain_count == 1
    assert result.fragment_length == len("top")


def test_features_for_url_with_credentials_and_port() -> None:
    c = _components(
        scheme="https",
        host="secure.example.com",
        path="/admin",
        username="admin",
        password="secret",
        port=8443,
    )
    result = _extract(c)

    assert result.has_credentials is True
    assert result.has_port is True
    assert result.uses_default_port is False
    assert result.at_sign_count == 1


def test_features_for_ip_address_url() -> None:
    c = _components(scheme="http", host="192.168.1.1", path="/admin")
    result = _extract(c)

    assert result.host_length == len("192.168.1.1")
    assert result.digit_count > 0
    assert result.dot_count > 0


def test_extractor_is_deterministic() -> None:
    """Same input always produces identical output."""
    c = _components(
        host="sub.example.com",
        path="/a/b/c",
        query="x=1&y=2",
        fragment="sec",
    )
    first = StructuralUrlFeatureExtractor().extract(c)
    second = StructuralUrlFeatureExtractor().extract(c)

    assert first == second
