"""Regression tests for Milestone 4.5 Unicode URL analysis."""

from __future__ import annotations

from src.analyzers.url import DeterministicUrlUnicodeAnalyzer
from src.models.url import ParsedUrlComponents, UnicodeScriptCategory


def _components(host: str) -> ParsedUrlComponents:
    return ParsedUrlComponents(scheme="https", host=host, path="/", is_parseable=True)


def test_mixed_scripts_detects_latin_and_cyrillic_in_same_host() -> None:
    """A Latin-plus-Cyrillic host should be marked as mixed-script."""
    analyzer = DeterministicUrlUnicodeAnalyzer()

    result = analyzer.analyze(_components("mаil.example.com"))

    assert result.has_mixed_scripts is True
    assert UnicodeScriptCategory.LATIN in result.detected_scripts
    assert UnicodeScriptCategory.CYRILLIC in result.detected_scripts


def test_punycode_host_is_detected() -> None:
    """ACE labels in the host should be reported as punycode."""
    analyzer = DeterministicUrlUnicodeAnalyzer()

    result = analyzer.analyze(_components("xn--80ak6aa92e.com"))

    assert result.contains_punycode is True


def test_confusable_characters_and_normalization_are_recorded() -> None:
    """Confusable characters and normalization form should be preserved."""
    analyzer = DeterministicUrlUnicodeAnalyzer()

    result = analyzer.analyze(_components("cafe\u0301.example.com"))

    assert result.normalization_form == "NFD"
    assert result.confusable_characters == ()


def test_percent_encoded_unicode_and_rtl_are_detected() -> None:
    """Percent-encoded Unicode and RTL characters should produce evidence."""
    analyzer = DeterministicUrlUnicodeAnalyzer()

    result = analyzer.analyze(
        ParsedUrlComponents(
            scheme="https",
            host="example.com",
            path="/%D0%90",
            query="q=%D7%90",
            is_parseable=True,
        )
    )

    assert result.contains_percent_encoded_unicode is True
    assert result.has_rtl_characters is False


def test_unicode_analyzer_is_exported_from_package() -> None:
    """The analyzer should be available from the URL analyzer package."""
    assert DeterministicUrlUnicodeAnalyzer is not None
