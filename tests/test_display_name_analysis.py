"""Unit tests for deterministic display-name analysis."""

from __future__ import annotations

from src.analyzers.sender.display_name import DeterministicDisplayNameAnalyzer
from src.models.display_name import (
    DisplayNameAnalysisPolicy,
    DisplayNameLexicon,
    ImpersonationIndicator,
)


def _analyzer() -> DeterministicDisplayNameAnalyzer:
    """Build a deterministic analyzer fixture with explicit vocabulary."""
    return DeterministicDisplayNameAnalyzer(
        lexicon=DisplayNameLexicon(
            organization_names=("Microsoft",),
            security_keywords=("security", "verify"),
            urgency_words=("urgent",),
            billing_words=("invoice",),
            support_words=("support",),
            administrator_names=("administrator",),
        ),
        policy=DisplayNameAnalysisPolicy(
            minimum_alphabetic_characters=4,
            uppercase_ratio_threshold=0.75,
            excessive_punctuation_threshold=3,
        ),
    )


def test_extracts_all_configured_lexical_categories() -> None:
    """Configured organization and category terms are reported independently."""
    result = _analyzer().analyze(
        "Microsoft Security Support Administrator - Urgent Invoice"
    )

    assert result.organization_names == ("microsoft",)
    assert result.security_keywords == ("security",)
    assert result.urgency_words == ("urgent",)
    assert result.billing_words == ("invoice",)
    assert result.support_words == ("support",)
    assert result.administrator_names == ("administrator",)


def test_reports_capitalization_and_excessive_punctuation_observations() -> None:
    """Formatting observations are threshold-driven and deterministic."""
    result = _analyzer().analyze("MICROSOFT SECURITY!!!!")

    assert result.is_suspiciously_capitalized is True
    assert result.uppercase_ratio == 1.0
    assert result.punctuation_count == 4
    assert result.has_excessive_punctuation is True


def test_reports_contextual_impersonation_indicators_without_a_verdict() -> None:
    """Organization context is preserved as evidence rather than a classification."""
    result = _analyzer().analyze("Microsoft Security Support")

    assert (
        ImpersonationIndicator.ORGANIZATION_REFERENCE
        in result.impersonation_indicators
    )
    assert (
        ImpersonationIndicator.ORGANIZATION_SECURITY_CONTEXT
        in result.impersonation_indicators
    )
    assert (
        ImpersonationIndicator.ORGANIZATION_SUPPORT_CONTEXT
        in result.impersonation_indicators
    )


def test_empty_display_name_is_safe_and_has_no_findings() -> None:
    """Missing display names produce an explicit empty result without failure."""
    result = _analyzer().analyze("   ")

    assert result.is_empty is True
    assert result.normalized_value == ""
    assert result.organization_names == ()
    assert result.impersonation_indicators == ()


def test_matching_respects_word_boundaries() -> None:
    """Terms embedded inside unrelated words do not produce false matches."""
    result = _analyzer().analyze("Microsoftware service")

    assert result.organization_names == ()
