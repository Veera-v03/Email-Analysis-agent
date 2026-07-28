"""Deterministic feature extraction for parsed domains.

The module intentionally produces observable characteristics only. It does not
perform reputation checks, make security decisions, or calculate risk scores.
"""

from __future__ import annotations

from collections import Counter
from itertools import groupby
from math import log2
from typing import Protocol, runtime_checkable

from src.models.domain import DomainParseResult
from src.models.domain_features import (
    DomainFeatureLexicon,
    DomainFeatureResult,
    TyposquattingIndicator,
)

DOT_SEPARATOR = "."
HYPHEN = "-"
PUNYCODE_PREFIX = "xn--"
ENTROPY_DECIMAL_PLACES = 6


@runtime_checkable
class DomainFeatureAnalyzer(Protocol):
    """Generate deterministic features from an already parsed domain."""

    def analyze(self, parsed_domain: DomainParseResult) -> DomainFeatureResult:
        """Return features without performing reputation or risk analysis."""


class DeterministicDomainFeatureAnalyzer:
    """Compute configurable, deterministic characteristics of a parsed domain."""

    def __init__(self, lexicon: DomainFeatureLexicon | None = None) -> None:
        """Create an analyzer with an immutable, caller-owned feature lexicon."""
        self._lexicon = lexicon or DomainFeatureLexicon()

    def analyze(self, parsed_domain: DomainParseResult) -> DomainFeatureResult:
        """Compute domain features without external I/O or security judgement."""
        analyzed_domain = self._analysis_text(parsed_domain)
        comparable_domain = analyzed_domain.casefold()
        core_label = (parsed_domain.second_level_domain or comparable_domain).casefold()
        suspicious_terms = self._matching_terms(
            comparable_domain,
            self._lexicon.suspicious_keywords,
        )
        brand_terms = self._matching_terms(
            core_label,
            self._lexicon.brand_keywords,
        )
        repeated_count = self._maximum_repeated_character_count(comparable_domain)

        return DomainFeatureResult(
            analyzed_domain=analyzed_domain,
            is_valid_domain=parsed_domain.is_valid,
            length=len(analyzed_domain),
            entropy=self._entropy(comparable_domain),
            hyphen_count=analyzed_domain.count(HYPHEN),
            digit_count=sum(character.isdigit() for character in analyzed_domain),
            contains_unicode=any(
                ord(character) > 127 for character in parsed_domain.raw_value
            ),
            contains_punycode=any(
                label.startswith(PUNYCODE_PREFIX)
                for label in comparable_domain.split(DOT_SEPARATOR)
            ),
            has_repeated_characters=repeated_count > 1,
            maximum_repeated_character_count=repeated_count,
            suspicious_keywords=suspicious_terms,
            brand_keywords=brand_terms,
            has_uncommon_tld=self._has_uncommon_tld(parsed_domain),
            typosquatting_indicators=self._typosquatting_indicators(
                core_label,
                self._lexicon.brand_keywords,
            ),
        )

    @staticmethod
    def _analysis_text(parsed_domain: DomainParseResult) -> str:
        """Select a bounded domain representation even for invalid input."""
        return parsed_domain.normalized_domain or parsed_domain.raw_value.strip()

    @staticmethod
    def _entropy(value: str) -> float:
        """Return Shannon entropy in bits for the normalized domain characters."""
        if not value:
            return 0.0
        character_counts = Counter(value)
        value_length = len(value)
        entropy = -sum(
            (count / value_length) * log2(count / value_length)
            for count in character_counts.values()
        )
        return round(entropy, ENTROPY_DECIMAL_PLACES)

    @staticmethod
    def _maximum_repeated_character_count(value: str) -> int:
        """Return the longest consecutive run of alphanumeric characters."""
        alphanumeric_value = "".join(
            character for character in value if character.isalnum()
        )
        if not alphanumeric_value:
            return 0
        return max(len(tuple(group)) for _, group in groupby(alphanumeric_value))

    @staticmethod
    def _matching_terms(value: str, terms: tuple[str, ...]) -> tuple[str, ...]:
        """Return unique normalized terms that occur in a feature target."""
        matches: list[str] = []
        for term in terms:
            normalized_term = term.strip().casefold()
            if (
                normalized_term
                and normalized_term in value
                and normalized_term not in matches
            ):
                matches.append(normalized_term)
        return tuple(matches)

    def _has_uncommon_tld(self, parsed_domain: DomainParseResult) -> bool:
        """Report whether a public suffix is absent from configured common TLDs."""
        if not parsed_domain.tld or not parsed_domain.has_known_public_suffix:
            return False
        common_tlds = {
            tld.strip().casefold() for tld in self._lexicon.common_tlds if tld.strip()
        }
        return bool(common_tlds) and parsed_domain.tld.casefold() not in common_tlds

    def _typosquatting_indicators(
        self,
        core_label: str,
        brand_terms: tuple[str, ...],
    ) -> tuple[TyposquattingIndicator, ...]:
        """Extract deterministic, bounded brand-similarity indicators.

        Exact brand matches are reported by ``brand_keywords`` and are not
        labeled as typosquatting. This method performs no visual-homoglyph or
        language-specific inference.
        """
        indicators: list[TyposquattingIndicator] = []
        for brand in brand_terms:
            normalized_brand = brand.strip().casefold()
            if not normalized_brand or core_label == normalized_brand:
                continue
            if (
                core_label.replace(HYPHEN, "") == normalized_brand
                and HYPHEN in core_label
            ):
                indicators.append(TyposquattingIndicator.HYPHENATED_BRAND)
            if self._is_at_most_one_edit_away(core_label, normalized_brand):
                indicators.append(TyposquattingIndicator.SINGLE_EDIT_DISTANCE)
        return tuple(dict.fromkeys(indicators))

    @staticmethod
    def _is_at_most_one_edit_away(first: str, second: str) -> bool:
        """Return whether two labels have Levenshtein distance of exactly one."""
        if first == second or abs(len(first) - len(second)) > 1:
            return False
        if len(first) == len(second):
            return (
                sum(left != right for left, right in zip(first, second, strict=True))
                == 1
            )

        longer, shorter = (
            (first, second) if len(first) > len(second) else (second, first)
        )
        index_longer = 0
        index_shorter = 0
        skipped_character = False
        while index_longer < len(longer) and index_shorter < len(shorter):
            if longer[index_longer] == shorter[index_shorter]:
                index_longer += 1
                index_shorter += 1
                continue
            if skipped_character:
                return False
            skipped_character = True
            index_longer += 1
        return True
