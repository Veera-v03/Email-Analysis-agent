"""Unit tests for canonical email-address normalization."""

from __future__ import annotations

from src.analyzers.sender.normalization import CanonicalEmailAddressNormalizer
from src.models.email_normalization import AddressNormalizationAction


def test_normalizes_case_and_outer_whitespace() -> None:
    """Case and surrounding whitespace produce a canonical email address."""
    result = CanonicalEmailAddressNormalizer().normalize("  Alice@EXAMPLE.COM  ")

    assert result.canonical_email == "alice@example.com"
    assert result.username == "alice"
    assert result.domain == "example.com"
    assert result.is_valid is True
    assert AddressNormalizationAction.CASE_NORMALIZED in result.actions
    assert (
        AddressNormalizationAction.LEADING_OR_TRAILING_WHITESPACE_REMOVED
        in result.actions
    )


def test_recovers_display_wrappers_and_malformed_separator_spacing() -> None:
    """Display formatting and recoverable separator defects are normalized."""
    result = CanonicalEmailAddressNormalizer().normalize(
        "Alice Example < ALICE..EXAMPLE@@Example..COM >"
    )

    assert result.canonical_email == "alice.example@example.com"
    assert result.is_valid is True
    assert AddressNormalizationAction.DISPLAY_WRAPPER_REMOVED in result.actions
    assert AddressNormalizationAction.INTERNAL_WHITESPACE_REMOVED in result.actions
    assert AddressNormalizationAction.REPEATED_AT_SEPARATOR_COLLAPSED in result.actions
    assert AddressNormalizationAction.REPEATED_DOT_SEPARATOR_COLLAPSED in result.actions


def test_normalizes_mailto_and_unicode_domains() -> None:
    """Mailto input and internationalized domains receive canonical encoding."""
    result = CanonicalEmailAddressNormalizer().normalize("mailto:User@Münich.Example")

    assert result.canonical_email == "user@xn--mnich-kva.example"
    assert result.is_valid is True
    assert AddressNormalizationAction.MAILTO_PREFIX_REMOVED in result.actions
    assert AddressNormalizationAction.DOMAIN_IDNA_ENCODED in result.actions


def test_invalid_addresses_return_evidence_without_canonical_mailbox() -> None:
    """Unrecoverable input does not raise and has no canonical representation."""
    result = CanonicalEmailAddressNormalizer().normalize("not-an-email")

    assert result.raw_value == "not-an-email"
    assert result.canonical_email is None
    assert result.username is None
    assert result.domain is None
    assert result.is_valid is False


def test_rejects_unsafe_address_characters() -> None:
    """Unsafe mailbox characters remain invalid after normalization attempts."""
    result = CanonicalEmailAddressNormalizer().normalize("user;drop@example.com")

    assert result.canonical_email is None
    assert result.is_valid is False


def test_bounds_oversized_invalid_input() -> None:
    """Very large invalid values are bounded before strict model validation."""
    result = CanonicalEmailAddressNormalizer().normalize("x" * 9_000)

    assert len(result.raw_value) == 8_192
    assert result.is_valid is False
