"""Public Suffix List-backed domain parsing utilities.

This module extracts domain structure only. It does not assess reputation,
similarity, ownership, or any security property of a domain.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Protocol, runtime_checkable

import tldextract

from src.models.domain import (
    MAX_DNS_LABEL_LENGTH,
    MAX_DOMAIN_INPUT_LENGTH,
    MAX_FQDN_LENGTH,
    DomainParseResult,
)

LOCALHOST_DOMAIN = "localhost"
DOT_SEPARATOR = "."
HYPHEN = "-"


@dataclass(frozen=True, slots=True)
class PublicSuffixComponents:
    """Represent domain components returned by a Public Suffix List resolver."""

    subdomain: str
    second_level_domain: str
    tld: str


@runtime_checkable
class PublicSuffixResolver(Protocol):
    """Resolve domain labels using a maintained Public Suffix List."""

    def resolve(self, normalized_domain: str) -> PublicSuffixComponents:
        """Return domain components for a syntactically valid normalized domain."""


@runtime_checkable
class DomainParser(Protocol):
    """Parse a raw domain into normalized structural components."""

    def parse(self, raw_domain: str) -> DomainParseResult:
        """Return structured components or a safe invalid-domain result."""


class TldExtractPublicSuffixResolver:
    """Resolve domains through tldextract's bundled Public Suffix List snapshot."""

    def __init__(self) -> None:
        """Create an offline resolver that never fetches suffix data at runtime."""
        self._extractor = tldextract.TLDExtract(
            suffix_list_urls=(),
            cache_dir=None,
        )

    def resolve(self, normalized_domain: str) -> PublicSuffixComponents:
        """Resolve a normalized ASCII domain into Public Suffix List components."""
        extracted = self._extractor(normalized_domain)
        return PublicSuffixComponents(
            subdomain=extracted.subdomain,
            second_level_domain=extracted.domain,
            tld=extracted.suffix,
        )


class PublicSuffixDomainParser:
    """Parse normal, multi-level, IDN, and localhost domain values safely."""

    def __init__(self, resolver: PublicSuffixResolver | None = None) -> None:
        """Create a parser with an injectable Public Suffix List resolver."""
        self._resolver = resolver or TldExtractPublicSuffixResolver()

    def parse(self, raw_domain: str) -> DomainParseResult:
        """Parse a raw domain value without raising on malformed input.

        Args:
            raw_domain: Candidate domain value, optionally surrounded by space or
                represented as a fully qualified domain name with a trailing dot.

        Returns:
            Extracted structural components or an invalid-domain result.
        """
        raw_value = self._bounded(raw_domain, MAX_DOMAIN_INPUT_LENGTH)
        normalized_domain, is_idn = self._normalize_domain(raw_value)
        if normalized_domain is None:
            return self._invalid(raw_value)

        if normalized_domain == LOCALHOST_DOMAIN:
            return DomainParseResult(
                raw_value=raw_value,
                normalized_domain=normalized_domain,
                root_domain=normalized_domain,
                second_level_domain=normalized_domain,
                is_valid=True,
                is_localhost=True,
                is_idn=is_idn,
            )

        components = self._resolver.resolve(normalized_domain)
        if not components.tld or not components.second_level_domain:
            return DomainParseResult(
                raw_value=raw_value,
                normalized_domain=normalized_domain,
                is_valid=True,
                is_idn=is_idn,
            )

        root_domain = (
            f"{components.second_level_domain}{DOT_SEPARATOR}{components.tld}"
        )
        return DomainParseResult(
            raw_value=raw_value,
            normalized_domain=normalized_domain,
            subdomain=components.subdomain or None,
            root_domain=root_domain,
            second_level_domain=components.second_level_domain,
            tld=components.tld,
            is_valid=True,
            is_idn=is_idn,
            has_known_public_suffix=True,
        )

    @staticmethod
    def _bounded(value: str, maximum_length: int) -> str:
        """Bound retained input before strict output-model validation."""
        return value[:maximum_length]

    @staticmethod
    def _invalid(raw_value: str) -> DomainParseResult:
        """Build a non-throwing invalid-domain result."""
        return DomainParseResult(raw_value=raw_value, is_valid=False)

    @staticmethod
    def _normalize_domain(raw_value: str) -> tuple[str | None, bool]:
        """Trim, IDNA-encode, and validate a candidate DNS domain name."""
        candidate = raw_value.strip().removesuffix(DOT_SEPARATOR)
        if not candidate or len(candidate) > MAX_FQDN_LENGTH:
            return None, False

        source_is_idn = any(ord(character) > 127 for character in candidate) or any(
            label.casefold().startswith("xn--")
            for label in candidate.split(DOT_SEPARATOR)
        )
        try:
            normalized_labels = tuple(
                label.encode("idna").decode("ascii").casefold()
                for label in candidate.split(DOT_SEPARATOR)
            )
        except UnicodeError:
            return None, source_is_idn

        normalized_domain = DOT_SEPARATOR.join(normalized_labels)
        if not PublicSuffixDomainParser._is_valid_dns_name(normalized_domain):
            return None, source_is_idn
        return normalized_domain, source_is_idn

    @staticmethod
    def _is_valid_dns_name(domain: str) -> bool:
        """Validate DNS label structure after IDNA conversion."""
        if len(domain) > MAX_FQDN_LENGTH:
            return False
        for label in domain.split(DOT_SEPARATOR):
            if (
                not label
                or len(label) > MAX_DNS_LABEL_LENGTH
                or label.startswith(HYPHEN)
                or label.endswith(HYPHEN)
                or not all(
                    (character.isascii() and character.isalnum())
                    or character == HYPHEN
                    for character in label
                )
            ):
                return False
        return True
