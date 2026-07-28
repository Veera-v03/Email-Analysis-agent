"""Deterministic display-name analysis utilities.

The module extracts textual observations only. It does not determine sender
legitimacy, phishing status, or risk.
"""

from __future__ import annotations

import re
import unicodedata
from typing import Protocol, runtime_checkable

from src.models.display_name import (
    MAX_DISPLAY_NAME_INPUT_LENGTH,
    DisplayNameAnalysisPolicy,
    DisplayNameAnalysisResult,
    DisplayNameLexicon,
    ImpersonationIndicator,
)


@runtime_checkable
class DisplayNameAnalyzer(Protocol):
    """Analyze one display-name value into deterministic structured findings."""

    def analyze(self, raw_display_name: str) -> DisplayNameAnalysisResult:
        """Return findings without performing a security decision."""


class DeterministicDisplayNameAnalyzer:
    """Compute configurable lexical and formatting observations for a display name."""

    def __init__(
        self,
        lexicon: DisplayNameLexicon | None = None,
        policy: DisplayNameAnalysisPolicy | None = None,
    ) -> None:
        """Create an analyzer with immutable caller-owned terms and thresholds."""
        self._lexicon = lexicon or DisplayNameLexicon()
        self._policy = policy or DisplayNameAnalysisPolicy()

    def analyze(self, raw_display_name: str) -> DisplayNameAnalysisResult:
        """Generate deterministic observations for a display-name input.

        Args:
            raw_display_name: Display text extracted from an email address header.

        Returns:
            Structured lexical and formatting findings.
        """
        raw_value = raw_display_name[:MAX_DISPLAY_NAME_INPUT_LENGTH]
        normalized_value = " ".join(raw_value.split())
        comparable_value = normalized_value.casefold()
        alphabetic_count = sum(character.isalpha() for character in normalized_value)
        uppercase_count = sum(character.isupper() for character in normalized_value)
        uppercase_ratio = (
            uppercase_count / alphabetic_count if alphabetic_count else 0.0
        )
        punctuation_count = sum(
            unicodedata.category(character).startswith("P")
            for character in normalized_value
        )
        organization_names = self._matching_terms(
            comparable_value,
            self._lexicon.organization_names,
        )
        security_keywords = self._matching_terms(
            comparable_value,
            self._lexicon.security_keywords,
        )
        urgency_words = self._matching_terms(
            comparable_value,
            self._lexicon.urgency_words,
        )
        billing_words = self._matching_terms(
            comparable_value,
            self._lexicon.billing_words,
        )
        support_words = self._matching_terms(
            comparable_value,
            self._lexicon.support_words,
        )
        administrator_names = self._matching_terms(
            comparable_value,
            self._lexicon.administrator_names,
        )

        return DisplayNameAnalysisResult(
            raw_value=raw_value,
            normalized_value=normalized_value,
            is_empty=not normalized_value,
            organization_names=organization_names,
            security_keywords=security_keywords,
            urgency_words=urgency_words,
            billing_words=billing_words,
            support_words=support_words,
            administrator_names=administrator_names,
            uppercase_character_count=uppercase_count,
            alphabetic_character_count=alphabetic_count,
            uppercase_ratio=uppercase_ratio,
            is_suspiciously_capitalized=(
                alphabetic_count >= self._policy.minimum_alphabetic_characters
                and uppercase_ratio >= self._policy.uppercase_ratio_threshold
            ),
            punctuation_count=punctuation_count,
            has_excessive_punctuation=(
                punctuation_count >= self._policy.excessive_punctuation_threshold
            ),
            impersonation_indicators=self._impersonation_indicators(
                organization_names,
                security_keywords,
                support_words,
                administrator_names,
            ),
        )

    @staticmethod
    def _matching_terms(value: str, terms: tuple[str, ...]) -> tuple[str, ...]:
        """Return distinct configured terms found as textual boundaries in a value."""
        matches: list[str] = []
        for term in terms:
            normalized_term = term.strip().casefold()
            if (
                normalized_term
                and re.search(
                    rf"(?<!\w){re.escape(normalized_term)}(?!\w)",
                    value,
                )
                and normalized_term not in matches
            ):
                matches.append(normalized_term)
        return tuple(matches)

    @staticmethod
    def _impersonation_indicators(
        organization_names: tuple[str, ...],
        security_keywords: tuple[str, ...],
        support_words: tuple[str, ...],
        administrator_names: tuple[str, ...],
    ) -> tuple[ImpersonationIndicator, ...]:
        """Return contextual observations relevant to later impersonation review."""
        indicators: list[ImpersonationIndicator] = []
        if organization_names:
            indicators.append(ImpersonationIndicator.ORGANIZATION_REFERENCE)
        if administrator_names:
            indicators.append(ImpersonationIndicator.ADMINISTRATOR_REFERENCE)
        if organization_names and security_keywords:
            indicators.append(ImpersonationIndicator.ORGANIZATION_SECURITY_CONTEXT)
        if organization_names and support_words:
            indicators.append(ImpersonationIndicator.ORGANIZATION_SUPPORT_CONTEXT)
        return tuple(indicators)
