"""Unit tests for Public Suffix List-backed domain parsing."""

from __future__ import annotations

from dataclasses import dataclass

from src.analyzers.sender.domain import (
    PublicSuffixComponents,
    PublicSuffixDomainParser,
)


@dataclass(frozen=True)
class StaticSuffixResolver:
    """Deterministic resolver fixture for parser unit tests."""

    components: PublicSuffixComponents

    def resolve(self, normalized_domain: str) -> PublicSuffixComponents:
        """Return configured Public Suffix List components."""
        return self.components


def test_extracts_normal_domain_components() -> None:
    """A conventional domain yields all expected structural components."""
    parser = PublicSuffixDomainParser(
        StaticSuffixResolver(PublicSuffixComponents("mail", "example", "com"))
    )

    result = parser.parse("Mail.Example.COM")

    assert result.normalized_domain == "mail.example.com"
    assert result.subdomain == "mail"
    assert result.root_domain == "example.com"
    assert result.second_level_domain == "example"
    assert result.tld == "com"
    assert result.has_known_public_suffix is True


def test_extracts_multi_level_tld_components() -> None:
    """A resolver-provided multi-level public suffix is retained intact."""
    parser = PublicSuffixDomainParser(
        StaticSuffixResolver(PublicSuffixComponents("alerts", "example", "co.uk"))
    )

    result = parser.parse("alerts.example.co.uk")

    assert result.subdomain == "alerts"
    assert result.root_domain == "example.co.uk"
    assert result.second_level_domain == "example"
    assert result.tld == "co.uk"


def test_normalizes_unicode_and_punycode_idn_domains() -> None:
    """Unicode and punycode input normalize to the same ASCII domain form."""
    resolver = StaticSuffixResolver(
        PublicSuffixComponents("", "xn--mnich-kva", "example")
    )
    parser = PublicSuffixDomainParser(resolver)

    unicode_result = parser.parse("Münich.Example")
    punycode_result = parser.parse("XN--MNICH-KVA.EXAMPLE")

    assert unicode_result.normalized_domain == "xn--mnich-kva.example"
    assert unicode_result.is_idn is True
    assert punycode_result.normalized_domain == "xn--mnich-kva.example"
    assert punycode_result.is_idn is True


def test_supports_localhost_without_public_suffix_resolution() -> None:
    """Localhost is valid local infrastructure, not a public-suffix domain."""
    result = PublicSuffixDomainParser().parse("localhost")

    assert result.is_valid is True
    assert result.is_localhost is True
    assert result.root_domain == "localhost"
    assert result.tld is None
    assert result.has_known_public_suffix is False


def test_malformed_domains_return_safe_invalid_results() -> None:
    """Malformed values do not raise and do not expose parsed components."""
    parser = PublicSuffixDomainParser(
        StaticSuffixResolver(PublicSuffixComponents("", "example", "com"))
    )

    for malformed_domain in ("", "example..com", "-example.com", "example .com"):
        result = parser.parse(malformed_domain)

        assert result.is_valid is False
        assert result.normalized_domain is None
        assert result.root_domain is None


def test_trailing_fqdn_dot_is_normalized() -> None:
    """A fully qualified domain name with a trailing dot remains parseable."""
    parser = PublicSuffixDomainParser(
        StaticSuffixResolver(PublicSuffixComponents("", "example", "com"))
    )

    result = parser.parse("example.com.")

    assert result.normalized_domain == "example.com"
    assert result.root_domain == "example.com"
