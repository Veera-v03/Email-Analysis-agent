"""Unit tests for deterministic domain feature analysis."""

from __future__ import annotations

from src.analyzers.sender.domain_features import DeterministicDomainFeatureAnalyzer
from src.models.domain import DomainParseResult
from src.models.domain_features import (
    DomainFeatureLexicon,
    TyposquattingIndicator,
)


def _parsed_domain(
    normalized_domain: str,
    second_level_domain: str,
    tld: str,
    *,
    raw_value: str | None = None,
) -> DomainParseResult:
    """Create a valid parsed-domain fixture for deterministic feature tests."""
    return DomainParseResult(
        raw_value=raw_value or normalized_domain,
        normalized_domain=normalized_domain,
        root_domain=f"{second_level_domain}.{tld}",
        second_level_domain=second_level_domain,
        tld=tld,
        is_valid=True,
        has_known_public_suffix=True,
    )


def test_computes_character_features_and_configured_keyword_matches() -> None:
    """Deterministic metrics and injected keyword policy are reported as evidence."""
    lexicon = DomainFeatureLexicon(
        suspicious_keywords=("secure", "verify"),
        brand_keywords=("paypal",),
        common_tlds=("com", "org"),
    )
    parsed = _parsed_domain("secure-paypal7.com", "secure-paypal7", "com")

    result = DeterministicDomainFeatureAnalyzer(lexicon).analyze(parsed)

    assert result.length == len("secure-paypal7.com")
    assert result.entropy > 0
    assert result.hyphen_count == 1
    assert result.digit_count == 1
    assert result.suspicious_keywords == ("secure",)
    assert result.brand_keywords == ("paypal",)
    assert result.has_uncommon_tld is False


def test_reports_unicode_and_punycode_separately() -> None:
    """Unicode source evidence and canonical punycode labels are both observable."""
    parsed = _parsed_domain(
        "xn--mnich-kva.example",
        "xn--mnich-kva",
        "example",
        raw_value="Münich.Example",
    )

    result = DeterministicDomainFeatureAnalyzer().analyze(parsed)

    assert result.contains_unicode is True
    assert result.contains_punycode is True


def test_reports_repeated_characters_and_uncommon_configured_tld() -> None:
    """Repetition and policy-relative suffix rarity remain deterministic features."""
    parsed = _parsed_domain("gooooogle.zip", "gooooogle", "zip")
    lexicon = DomainFeatureLexicon(common_tlds=("com", "org"))

    result = DeterministicDomainFeatureAnalyzer(lexicon).analyze(parsed)

    assert result.has_repeated_characters is True
    assert result.maximum_repeated_character_count == 5
    assert result.has_uncommon_tld is True


def test_reports_deterministic_typosquatting_indicators_without_a_verdict() -> None:
    """One-edit and hyphen-insertion similarities are exposed as separate facts."""
    lexicon = DomainFeatureLexicon(brand_keywords=("paypal",))
    one_edit = _parsed_domain("paypa1.com", "paypa1", "com")
    hyphenated = _parsed_domain("pay-pal.com", "pay-pal", "com")
    analyzer = DeterministicDomainFeatureAnalyzer(lexicon)

    one_edit_result = analyzer.analyze(one_edit)
    hyphenated_result = analyzer.analyze(hyphenated)

    assert (
        TyposquattingIndicator.SINGLE_EDIT_DISTANCE
        in one_edit_result.typosquatting_indicators
    )
    assert (
        TyposquattingIndicator.HYPHENATED_BRAND
        in hyphenated_result.typosquatting_indicators
    )


def test_invalid_domain_input_still_returns_safe_deterministic_features() -> None:
    """Invalid parser output is featureable without external calls or failures."""
    parsed = DomainParseResult(raw_value="bad..domain", is_valid=False)

    result = DeterministicDomainFeatureAnalyzer().analyze(parsed)

    assert result.analyzed_domain == "bad..domain"
    assert result.is_valid_domain is False
    assert result.length == len("bad..domain")
    assert result.has_uncommon_tld is False
